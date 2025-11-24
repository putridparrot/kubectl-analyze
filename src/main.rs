use std::ops::Deref;
use clap::Parser;
use k8s_openapi::api::apps::v1::Deployment;
use kube::{api::Api, Client};
use k8s_openapi::api::core::v1::{Pod, Service};
use jsonpath_lib::select;
use serde_json::Value;
use k8s_rule::K8sRule;
use crate::args::Args;
use colored::*;

mod k8s_rule;
mod args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let cli = Args::parse();

    let fs: String = std::fs::read_to_string(cli.rules_file.unwrap_or("rules.json".to_string()))?;
    let rules: Vec<K8sRule> = serde_json::from_str(fs.as_str())?;

    let namespace = cli.namespace.unwrap_or("default".to_string());

    println!("{}", format!("Analyzing Kubernetes in namespace '{}'", namespace).bright_white().bold().underline());

    let client = Client::try_default().await?;

    // Deployments
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    for d in deployments.list(&Default::default()).await? {
        let json = serde_json::to_value(&d)?;
        run_rules(&rules, "Deployment", &json, d.metadata.name.as_deref().unwrap_or(""));
    }

    // Pods
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    for p in pods.list(&Default::default()).await? {
        let json = serde_json::to_value(&p)?;
        run_rules(&rules, "Pod", &json, p.metadata.name.as_deref().unwrap_or(""));
    }

    // Services
    let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
    for s in services.list(&Default::default()).await? {
        let json = serde_json::to_value(&s)?;
        run_rules(&rules, "Service", &json, s.metadata.name.as_deref().unwrap_or(""));
    }

    Ok(())
}

fn run_rules(rules: &[K8sRule], resource_type: &str, json: &Value, name: &str) {
    for rule in rules.iter().filter(|r| r.resource == resource_type) {
        let passed = evaluate_rule(rule, json);
        let output = format!("{} on {} '{}'",
            rule.name,
            resource_type,
            name);

        if passed {
            println!("{}: {}", colour_severity(&rule.severity), output.bright_green());
        } else {
            println!("{}: {}", colour_severity(&rule.severity), output.red());
        }
    }
}

fn colour_severity(severity: &k8s_rule::Severity) -> ColoredString {
    match severity {
        k8s_rule::Severity::Information => severity.to_string().blue(),
        k8s_rule::Severity::Warning => severity.to_string().yellow(),
        k8s_rule::Severity::Error => severity.to_string().red(),
    }
}

fn evaluate_rule(rule: &K8sRule, resource: &Value) -> bool {
    let results = select(resource, &rule.jsonpath).unwrap_or_default();
    if results.is_empty() {
        return false;
    }
    let actual = &results[0];
    match rule.operator.as_str() {
        ">=" => actual.as_i64().unwrap_or(0) >= rule.value.as_i64().unwrap(),
        "<=" => actual.as_i64().unwrap_or(0) <= rule.value.as_i64().unwrap(),
        "==" => actual.as_str() == rule.value.as_str(),
        "!=" => actual.as_str() != rule.value.as_str(),
        _ => false,
    }
}
