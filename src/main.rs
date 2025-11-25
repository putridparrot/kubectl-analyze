use clap::Parser;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use kube::{api::Api, Client};
use k8s_openapi::api::core::v1::{ConfigMap, LimitRange, Pod, ResourceQuota, Secret, Service};
use jsonpath_lib::select;
use serde_json::{to_value, Value};
use k8s_rule::K8sRule;
use crate::args::Args;
use colored::*;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
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
        let json = to_value(&d)?;
        run_rules(&rules, Resource::Deployment, &json, d.metadata.name.as_deref().unwrap_or(""));
    }

    // Pods
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    for p in pods.list(&Default::default()).await? {
        let json = to_value(&p)?;
        run_rules(&rules, Resource::Pod, &json, p.metadata.name.as_deref().unwrap_or(""));
    }

    // Services
    let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
    for s in services.list(&Default::default()).await? {
        let json = to_value(&s)?;
        run_rules(&rules, Resource::Service, &json, s.metadata.name.as_deref().unwrap_or(""));
    }

    // Ingress
    let ingresses: Api<Ingress> = Api::namespaced(client.clone(), &namespace);
    for ing in ingresses.list(&Default::default()).await? {
        let json = to_value(&ing)?;
        run_rules(&rules, Resource::Ingress, &json, ing.metadata.name.as_deref().unwrap_or(""));
    }

    // ConfigMap
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
    for cm in configmaps.list(&Default::default()).await? {
        let json = to_value(&cm)?;
        run_rules(&rules, Resource::ConfigMap, &json, cm.metadata.name.as_deref().unwrap_or(""));
    }

    // HorizontalPodAutoscaler
    let hpas: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), &namespace);
    for hpa in hpas.list(&Default::default()).await? {
        let json = to_value(&hpa)?;
        run_rules(&rules, Resource::HorizontalPodAutoscaler, &json, hpa.metadata.name.as_deref().unwrap_or(""));
    }

    // Secret
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
    for secret in secrets.list(&Default::default()).await? {
        let json = to_value(&secret)?;
        run_rules(
            &rules,
            Resource::Secret, // assuming you have a Resource enum variant for Secret
            &json,
            secret.metadata.name.as_deref().unwrap_or(""),
        );
    }

    // ResourceQuota
    let quotas: Api<ResourceQuota> = Api::namespaced(client.clone(), &namespace);
    for quota in quotas.list(&Default::default()).await? {
        let json = to_value(&quota)?;
        run_rules(
            &rules,
            Resource::ResourceQuota, // add a Resource enum variant for quotas
            &json,
            quota.metadata.name.as_deref().unwrap_or(""),
        );
    }

    // StatefulSet
    let statefulsets: Api<StatefulSet> = Api::namespaced(client.clone(), &namespace);
    for sts in statefulsets.list(&Default::default()).await? {
        let json = to_value(&sts)?;
        run_rules(
            &rules,
            Resource::StatefulSet, // add a Resource enum variant for StatefulSet
            &json,
            sts.metadata.name.as_deref().unwrap_or(""),
        );
    }

    // DaemonSet
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), &namespace);
    for ds in daemonsets.list(&Default::default()).await? {
        let json = to_value(&ds)?;
        run_rules(
            &rules,
            Resource::DaemonSet, // add a Resource enum variant for DaemonSet
            &json,
            ds.metadata.name.as_deref().unwrap_or(""),
        );
    }

    let jobs: Api<Job> = Api::namespaced(client.clone(), &namespace);
    for job in jobs.list(&Default::default()).await? {
        let json = to_value(&job)?;
        run_rules(
            &rules,
            Resource::Job, // add a Resource enum variant for Job
            &json,
            job.metadata.name.as_deref().unwrap_or(""),
        );
    }

    let cronjobs: Api<CronJob> = Api::namespaced(client.clone(), &namespace);
    for cj in cronjobs.list(&Default::default()).await? {
        let json = to_value(&cj)?;
        run_rules(
            &rules,
            Resource::CronJob, // add a Resource enum variant for CronJob
            &json,
            cj.metadata.name.as_deref().unwrap_or(""),
        );
    }

    // LimitRange
    let limitranges: Api<LimitRange> = Api::namespaced(client.clone(), &namespace);
    for lr in limitranges.list(&Default::default()).await? {
        let json = to_value(&lr)?;
        run_rules(
            &rules,
            Resource::LimitRange, // add a Resource enum variant for LimitRange
            &json,
            lr.metadata.name.as_deref().unwrap_or(""),
        );
    }


    Ok(())
}

fn run_rules(rules: &[K8sRule], resource_type: Resource, json: &Value, name: &str) {
    println!("Resource Type: {}", resource_type.to_string().bright_white().bold());

    for rule in rules.iter().filter(|r| r.resource.to_string() == resource_type.to_string()) {
        let passed = evaluate_rule(rule, json);
        let output = format!("{} on {} '{}'",
            rule.name,
            resource_type,
            name);

        if passed {
            println!("{}: (Category {}) {}", colour_severity(&rule.severity), rule.category, output.bright_green());
        } else {
            println!("{}: (Category {}) {}", colour_severity(&rule.severity), rule.category, output.red());
        }
        println!("\t{}", &rule.description);
        println!("\t{} {} {}", &rule.jsonpath.italic(), &rule.operator.bright_white(),
                 &rule.value
                     .as_ref()
                     .map_or("<none>".to_string(), |v| v.to_string())
                     .italic());
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

    let value = rule.value.as_ref().unwrap_or(&Value::Null);

    let actual = &results[0];
    match rule.operator.as_str() {
        ">"  => actual.as_i64().unwrap_or(0) >  value.as_i64().unwrap(),
        ">=" => actual.as_i64().unwrap_or(0) >= value.as_i64().unwrap(),
        "<"  => actual.as_i64().unwrap_or(0) <  value.as_i64().unwrap(),
        "<=" => actual.as_i64().unwrap_or(0) <= value.as_i64().unwrap(),
        "==" => actual.as_str() == value.as_str(),
        "!=" => actual.as_str() != value.as_str(),
        "exists" => !actual.is_null(),
        "in" => {
            if let (Some(actual_str), Some(arr)) = (actual.as_str(), value.as_array()) {
                arr.iter().any(|v| v.as_str() == Some(actual_str))
            } else {
                false
            }
        },
        "between" => {
            if let Some(arr) = value.as_array() {
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
            if let (Some(actual_str), Some(value_str)) = (actual.as_str(), value.as_str()) {
                !actual_str.contains(value_str)
            } else {
                false
            }
        },
        _ => false,
    }
}
