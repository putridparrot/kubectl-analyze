use clap::Parser;
use k8s_openapi::api::apps::v1::Deployment;
use kube::{api::Api, Client};
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Service};
use jsonpath_lib::select;
use serde_json::Value;
use k8s_rule::K8sRule;
use crate::args::Args;
use colored::*;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::networking::v1::Ingress;
use crate::k8s_rule::Resource;

mod k8s_rule;
mod args;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let cli = Args::parse();

    let fs: String = std::fs::read_to_string(cli.rules_file.unwrap_or("rules.json".to_string()))?;
    let rules: Vec<K8sRule> = serde_json::from_str(fs.as_str())?;

    let namespace = cli.namespace.unwrap_or("default".to_string());

    println!("{}", format!("Analyzing Kubernetes namespace '{}'", namespace).bright_white().bold().underline());

    let client = Client::try_default().await?;

    // Deployments
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    for d in deployments.list(&Default::default()).await? {
        let json = serde_json::to_value(&d)?;
        run_rules(&rules, Resource::Deployment, &json, d.metadata.name.as_deref().unwrap_or(""));
    }

    // Pods
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    for p in pods.list(&Default::default()).await? {
        let json = serde_json::to_value(&p)?;
        run_rules(&rules, Resource::Pod, &json, p.metadata.name.as_deref().unwrap_or(""));
    }

    // Services
    let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
    for s in services.list(&Default::default()).await? {
        let json = serde_json::to_value(&s)?;
        run_rules(&rules, Resource::Service, &json, s.metadata.name.as_deref().unwrap_or(""));
    }

    // Ingress
    let ingresses: Api<Ingress> = Api::namespaced(client.clone(), &namespace);
    for ing in ingresses.list(&Default::default()).await? {
        let json = serde_json::to_value(&ing)?;
        run_rules(&rules, Resource::Ingress, &json, ing.metadata.name.as_deref().unwrap_or(""));
    }

    // ConfigMap
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
    for cm in configmaps.list(&Default::default()).await? {
        let json = serde_json::to_value(&cm)?;
        run_rules(&rules, Resource::ConfigMap, &json, cm.metadata.name.as_deref().unwrap_or(""));
    }

    // HorizontalPodAutoscaler
    let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), &namespace);
    for hpa in hpas.list(&Default::default()).await? {
        let json = serde_json::to_value(&hpa)?;
        run_rules(&rules, Resource::HorizontalPodAutoscaler, &json, hpa.metadata.name.as_deref().unwrap_or(""));
    }

    Ok(())
}

fn run_rules(rules: &[K8sRule], resource_type: Resource, json: &Value, name: &str) {
    for rule in rules.iter().filter(|r| r.resource.to_string() == resource_type.to_string()) {
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
        k8s_rule::Severity::Critical => severity.to_string().bright_red(),
    }
}

fn evaluate_rule(rule: &K8sRule, resource: &Value) -> bool {
    let results = select(resource, &rule.jsonpath).unwrap_or_default();
    if results.is_empty() {
        return false;
    }
    let actual = &results[0];
    match rule.operator.as_str() {
        ">"  => actual.as_i64().unwrap_or(0) >  rule.value.as_i64().unwrap(),
        ">=" => actual.as_i64().unwrap_or(0) >= rule.value.as_i64().unwrap(),
        "<"  => actual.as_i64().unwrap_or(0) <  rule.value.as_i64().unwrap(),
        "<=" => actual.as_i64().unwrap_or(0) <= rule.value.as_i64().unwrap(),
        "==" => actual.as_str() == rule.value.as_str(),
        "!=" => actual.as_str() != rule.value.as_str(),
        "exists" => !actual.is_null(),
        "in" => {
            if let (Some(actual_str), Some(arr)) = (actual.as_str(), rule.value.as_array()) {
                arr.iter().any(|v| v.as_str() == Some(actual_str))
            } else {
                false
            }
        },
        "between" => {
            if let Some(arr) = rule.value.as_array() {
                if arr.len() == 2 {
                    let lower = arr[0].as_i64().unwrap_or(i64::MIN);
                    let upper = arr[1].as_i64().unwrap_or(i64::MAX);
                    let actual_val = actual.as_i64().unwrap_or(0);
                    actual_val >= lower && actual_val <= upper
                } else {
                    false
                }
            } else {
                false
            }
        },
        "notContains" => {
            if let (Some(actual_str), Some(value_str)) = (actual.as_str(), rule.value.as_str()) {
                !actual_str.contains(value_str)
            } else {
                false
            }
        },
        _ => false,
    }
}
