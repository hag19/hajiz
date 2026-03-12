use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "hagbox")]
#[command(about = "Default-deny application sandbox for Linux")]
pub struct Cli {
    #[arg(long)]
    pub profile: Option<PathBuf>,

    #[arg(long)]
    pub no_net: bool,

    #[arg(long)]
    pub paranoid: bool,

    #[arg(long)]
    pub verbose: bool,

    #[arg(value_name = "BINARY")]
    pub binary: PathBuf,

    #[arg(value_name = "ARGS", trailing_var_arg = true)]
    pub args: Vec<String>,
}
