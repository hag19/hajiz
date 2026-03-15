use hajiz::{
    isolation::IsolationConfig,
    runtime::{
        process::{SandboxProcess, SpawnOptions},
    },
};

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("usage: hajiz <binary> [args...]");
        std::process::exit(2);
    }

    let binary = std::path::PathBuf::from(args.remove(0));

    let result = SandboxProcess::spawn(SpawnOptions {
        binary,
        args,
        verbose: false,
        isolation: IsolationConfig::default(),
    })
    .and_then(|sandbox| {
        sandbox.monitor().map(|status| {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        })
    });

    if let Err(e) = result {
        eprintln!("[hajiz] error: {e}");
        std::process::exit(1);
    }
}

