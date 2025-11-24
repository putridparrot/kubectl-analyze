use clap::{Parser};

#[derive(Parser)]
#[command(name = "kubectl-analyze")]
#[command(about = "Analyze Kubernetes", long_about = None)]
pub struct Args {
    /// The rules file to use
    #[arg(short, long)]
    pub rules_file: Option<String>,

    /// The Kubernetes namespace to use
    #[arg(short, long)]
    pub namespace: Option<String>,
}