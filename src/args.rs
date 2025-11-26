use clap::{Parser};
use crate::k8s_rule::{Category, Resource, Severity};

#[derive(Parser)]
#[command(name = "kubectl-analyze")]
#[command(about = "Analyze Kubernetes", long_about = None)]
pub struct Args {
    /// The rules file to use
    #[arg(short = 'f', long = "file", default_value = "rules.json")]
    pub rules_file: Option<String>,

    /// The Kubernetes namespace to use
    #[arg(short, long)]
    pub namespace: Option<String>,

    /// The severity level to use, defaults to all levels
    #[arg(short, long)]
    pub level: Option<Severity>,

    /// The category to use, if not supplied all categories are used
    #[arg(short, long)]
    pub category: Option<Category>,

    /// The resource type to use, if not supplied all resources are used
    #[arg(short, long)]
    pub resource: Option<Resource>,
}