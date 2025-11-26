use clap::Parser;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use kube::{api::Api, Client, ResourceExt};
use k8s_openapi::api::core::v1::{ConfigMap, Endpoints, LimitRange, Namespace, PersistentVolume, PersistentVolumeClaim, Pod, ResourceQuota, Secret, Service, ServiceAccount};
use jsonpath_lib::select;
use serde_json::{to_value, Value};
use k8s_rule::K8sRule;
use crate::args::Args;
use colored::*;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass, NetworkPolicy};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::api::scheduling::v1::PriorityClass;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use serde::Serialize;
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
    process_resources(Api::<Deployment>::all(client.clone()), &rules, &Resource::Deployment).await?;

    // Pods
    process_resources(Api::<Pod>::all(client.clone()), &rules, &Resource::Pod).await?;

    // Services
    process_resources(Api::<Service>::all(client.clone()), &rules, &Resource::Service).await?;

    // Ingress
    process_resources(Api::<Ingress>::all(client.clone()), &rules, &Resource::Ingress).await?;

    // ConfigMap
    process_resources(Api::<ConfigMap>::all(client.clone()), &rules, &Resource::ConfigMap).await?;

    // HorizontalPodAutoscaler
    process_resources(Api::<HorizontalPodAutoscaler>::all(client.clone()), &rules, &Resource::HorizontalPodAutoscaler).await?;

    // Secret
    process_resources(Api::<Secret>::all(client.clone()), &rules, &Resource::Secret).await?;

    // ResourceQuota
    process_resources(Api::<ResourceQuota>::all(client.clone()), &rules, &Resource::ResourceQuota).await?;

    // StatefulSet
    process_resources(Api::<StatefulSet>::all(client.clone()), &rules, &Resource::StatefulSet).await?;

    // DaemonSet
    process_resources(Api::<DaemonSet>::all(client.clone()), &rules, &Resource::DaemonSet).await?;

    // Job
    process_resources(Api::<Job>::all(client.clone()), &rules, &Resource::Job).await?;

    // CronJob
    process_resources(Api::<CronJob>::all(client.clone()), &rules, &Resource::CronJob).await?;

    // LimitRange
    process_resources(Api::<LimitRange>::all(client.clone()), &rules, &Resource::LimitRange).await?;

    // VerticalPodAutoscaler
    //process_resources(Api::<VerticalPodAutoscaler>::all(client.clone()), &rules, &Resource::VerticalPodAutoscaler).await?;

    // ServiceAccount
    process_resources(Api::<ServiceAccount>::all(client.clone()), &rules, &Resource::ServiceAccount).await?;

    // NetworkPolicy
    process_resources(Api::<NetworkPolicy>::all(client.clone()), &rules, &Resource::NetworkPolicy).await?;

    // PriorityClass
    process_resources(Api::<PriorityClass>::all(client.clone()), &rules, &Resource::PriorityClass).await?;

    // PersistentVolumeClaim
    process_resources(Api::<PersistentVolumeClaim>::all(client.clone()), &rules, &Resource::PersistentVolumeClaim).await?;

    // PersistentVolume
    process_resources(Api::<PersistentVolume>::all(client.clone()), &rules, &Resource::PersistentVolume).await?;

    // IngressClass
    process_resources(Api::<IngressClass>::all(client.clone()), &rules, &Resource::IngressClass).await?;

    // PodDisruptionBudget
    process_resources(Api::<PodDisruptionBudget>::all(client.clone()), &rules, &Resource::PodDisruptionBudget).await?;

    // CustomResourceDefinition
    process_resources(Api::<CustomResourceDefinition>::all(client.clone()), &rules, &Resource::CustomResourceDefinition).await?;

    // Endpoints
    process_resources(Api::<Endpoints>::all(client.clone()), &rules, &Resource::Endpoints).await?;

    // EndpointSlice
    process_resources(Api::<EndpointSlice>::all(client.clone()), &rules, &Resource::EndpointSlice).await?;

    // Namespace
    process_resources(Api::<Namespace>::all(client.clone()), &rules, &Resource::Namespace).await?;

    Ok(())
}

async fn process_resources<K>(api: Api<K>, rules: &Vec<K8sRule>, resource: &Resource) -> anyhow::Result<()>
where
    K: kube::Resource + serde::de::DeserializeOwned + Clone + std::fmt::Debug + Serialize + Send + Sync + 'static,
{
    for item in api.list(&Default::default()).await? {
        let json = to_value(&item)?;
        run_rules(
            &rules,
            resource,
            &json,
            item.name_any().as_str(),
        );
    }

    Ok(())
}

fn run_rules(rules: &[K8sRule], resource_type: &Resource, json: &Value, name: &str) {
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
                     .map_or("null".to_string(), |v| v.to_string()) // need to handle when value is meant to be null
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