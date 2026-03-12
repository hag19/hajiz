use clap::Parser;

use hagbox::cli::args::Cli;

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        println!("[hagbox] starting with command: {:?}", cli.binary);
    }

    println!("hagbox scaffold initialized. Binary requested: {:?}", cli.binary);
}
