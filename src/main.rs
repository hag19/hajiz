use clap::Parser;

use hagbox::{
    cli::args::{Cli, Command},
    runtime::{
        pidfile,
        process::SandboxProcess,
    },
};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run(args) => {
            match SandboxProcess::spawn(&args) {
                Ok(sandbox) => sandbox.monitor()
                    .map(|status| {
                        if !status.success() {
                            std::process::exit(status.code().unwrap_or(1));
                        }
                    })
                    .map_err(|e| e),
                Err(e) => Err(e),
            }
        }

        Command::Kill(args) => {
            // If target looks like a number treat it as a raw PID,
            // otherwise treat it as a named sandbox.
            match args.target.parse::<u32>() {
                Ok(pid) => SandboxProcess::kill_by_pid(pid, args.force)
                    .map(|_| ()),
                Err(_)  => SandboxProcess::kill_by_name(&args.target, args.force)
                    .map(|_| ()),
            }
        }

        Command::List => {
            let sandboxes = pidfile::list_all();
            if sandboxes.is_empty() {
                println!("No running hagbox sandboxes found.");
            } else {
                println!("{:<20} {}", "NAME", "PID");
                println!("{}", "-".repeat(28));
                for (name, pid) in sandboxes {
                    println!("{:<20} {}", name, pid);
                }
            }
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("[hagbox] error: {e}");
        std::process::exit(1);
    }
}

