use clap::{Parser};

#[derive(Parser)]
#[command(name = "kubectl-analyze")]
#[command(about = "Analyze Kubernetes", long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub rules_file: String
}