use std::{
    ffi::c_int,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

use crate::{
    cli::args::RunArgs,
    error::HagboxError,
    runtime::pidfile,
};

// ---------------------------------------------------------------------------
// Global termination flag — written only from signal handler (atomic, safe).
// ---------------------------------------------------------------------------
static TERMINATE_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination(_sig: c_int) {
    TERMINATE_REQUESTED.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// SandboxProcess
// ---------------------------------------------------------------------------

/// A sandboxed child process managed by hagbox.
pub struct SandboxProcess {
    /// The underlying OS child handle.
    child: Child,
    /// OS process ID.
    pub pid: u32,
    /// Optional human-readable name (from --name).
    pub name: Option<String>,
    /// Path to the pidfile written on launch.
    pidfile_name: Option<String>,
}

impl SandboxProcess {
    /// Spawn the target binary and register the process in the pidfile store.
    pub fn spawn(args: &RunArgs) -> Result<Self, HagboxError> {
        // Validate the binary exists.
        if !args.binary.exists() {
            return Err(HagboxError::Config(format!(
                "binary not found: {}",
                args.binary.display()
            )));
        }

        if args.verbose {
            eprintln!("[hagbox] spawning: {}", args.binary.display());
        }

        let child = Command::new(&args.binary)
            .args(&args.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let pid = child.id();

        // Write pidfile when a name is given.
        let pidfile_name = if let Some(ref name) = args.name {
            pidfile::write(name, pid)?;
            if args.verbose {
                eprintln!("[hagbox] pidfile written  → /tmp/hagbox/{name}.pid (PID {pid})");
            }
            Some(name.clone())
        } else {
            None
        };

        eprintln!("[hagbox] sandboxed process started (PID {pid})");

        Ok(Self {
            child,
            pid,
            name: args.name.clone(),
            pidfile_name,
        })
    }

    // -----------------------------------------------------------------------
    // Monitoring & graceful shutdown
    // -----------------------------------------------------------------------

    /// Block until the child exits or a termination signal is received.
    /// On signal: SIGTERM → 2 s → SIGKILL → cleanup.
    pub fn monitor(mut self) -> Result<ExitStatus, HagboxError> {
        // Register SIGINT / SIGTERM handlers.
        // SAFETY: we only write to a static AtomicBool — correct for signal handlers.
        unsafe {
            signal::signal(Signal::SIGINT, signal::SigHandler::Handler(handle_termination))
                .map_err(|e| HagboxError::Isolation(format!("signal setup failed: {e}")))?;
            signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(handle_termination))
                .map_err(|e| HagboxError::Isolation(format!("signal setup failed: {e}")))?;
        }

        loop {
            // Check if the child has exited on its own.
            match self.child.try_wait()? {
                Some(status) => {
                    eprintln!("[hagbox] process exited: {status}");
                    self.cleanup();
                    return Ok(status);
                }
                None => {}
            }

            // Check if we received a termination signal.
            if TERMINATE_REQUESTED.load(Ordering::SeqCst) {
                eprintln!("[hagbox] termination signal received — killing sandbox (PID {})", self.pid);
                self.kill_child(false);
                // Wait for child to actually exit.
                let status = self.child.wait()?;
                eprintln!("[hagbox] sandbox terminated: {status}");
                self.cleanup();
                return Ok(status);
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    // -----------------------------------------------------------------------
    // Static kill helpers (used by `hagbox kill` subcommand)
    // -----------------------------------------------------------------------

    /// Kill a sandbox identified by a raw PID.
    pub fn kill_by_pid(pid: u32, force: bool) -> Result<(), HagboxError> {
        send_signal(pid, force)?;
        eprintln!("[hagbox] signal sent to PID {pid}");
        Ok(())
    }

    /// Kill a sandbox identified by name, looking up its PID from the pidfile.
    /// Also removes the pidfile after signalling.
    pub fn kill_by_name(name: &str, force: bool) -> Result<(), HagboxError> {
        let pid = pidfile::read(name)?;
        send_signal(pid, force)?;
        eprintln!("[hagbox] signal sent to '{name}' (PID {pid})");
        // Wait up to 3 s for the process to disappear, then prune the pidfile.
        wait_for_exit(pid, Duration::from_secs(3));
        pidfile::remove(name);
        eprintln!("[hagbox] pidfile removed for '{name}'");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Send SIGTERM, wait 2 seconds, then SIGKILL if still alive.
    fn kill_child(&mut self, force: bool) {
        let pid = self.pid;
        if force {
            eprintln!("[hagbox] sending SIGKILL to PID {pid}");
            let _ = send_signal(pid, true);
        } else {
            eprintln!("[hagbox] sending SIGTERM to PID {pid}");
            if send_signal(pid, false).is_err() {
                return; // Already dead.
            }
            // Give the process 2 seconds to exit gracefully.
            thread::sleep(Duration::from_secs(2));
            // Check if it's still alive.
            if self.child.try_wait().ok().flatten().is_none() {
                eprintln!("[hagbox] process did not exit — sending SIGKILL to PID {pid}");
                let _ = send_signal(pid, true);
            }
        }
    }

    /// Best-effort cleanup: remove pidfile, log cgroup path if applicable.
    fn cleanup(&mut self) {
        if let Some(ref name) = self.pidfile_name {
            pidfile::remove(name);
            eprintln!("[hagbox] pidfile removed for '{name}'");
        }
        // TODO (Phase 2): remove cgroup at /sys/fs/cgroup/hagbox/<pid>
        eprintln!("[hagbox] cleanup complete for PID {}", self.pid);
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Send SIGTERM (graceful) or SIGKILL (force) to a PID.
fn send_signal(pid: u32, force: bool) -> Result<(), HagboxError> {
    let nix_pid = Pid::from_raw(pid as i32);
    let sig = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    signal::kill(nix_pid, sig)
        .map_err(|e| HagboxError::Isolation(format!("kill({pid}) failed: {e}")))?;
    Ok(())
}

/// Poll until the process with `pid` disappears or `timeout` elapses.
fn wait_for_exit(pid: u32, timeout: Duration) {
    let nix_pid = Pid::from_raw(pid as i32);
    let step = Duration::from_millis(100);
    let mut elapsed = Duration::ZERO;
    while elapsed < timeout {
        // kill(pid, 0) — probe existence without delivering a signal.
        if signal::kill(nix_pid, None).is_err() {
            return; // Process is gone.
        }
        thread::sleep(step);
        elapsed += step;
    }
}
