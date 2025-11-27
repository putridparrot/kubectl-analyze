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
use crate::configuration::Configuration;
use crate::k8s_rule::{Category, Resource, Severity};
use crate::rules_updater::update_rules;

mod k8s_rule;
mod args;
mod rules_updater;
mod configuration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let cli = Args::parse();

    if cli.update {
        update_rules().await?;
        return Ok(());
    }

    let fs: String = std::fs::read_to_string(cli.rules_file.unwrap_or(Configuration::RULES_FILE.to_string()))?;
    let rules: Vec<K8sRule> = serde_json::from_str(fs.as_str())?;

    let namespace = cli.namespace.unwrap_or("default".to_string());

    let levels = cli.level
        .map(|level| level.included_levels())
        .unwrap_or_else(|| Vec::new());

    let category = cli.category;
    let resource = cli.resource;

    println!("{}", format!("Analyzing Kubernetes namespace '{}'", namespace).bright_white().bold().underline());

    let client = Client::try_default().await?;

    // Deployments
    process_resources(Api::<Deployment>::all(client.clone()), &rules, &Resource::Deployment, &levels, &category, &resource).await?;

    // Pods
    process_resources(Api::<Pod>::all(client.clone()), &rules, &Resource::Pod, &levels, &category, &resource).await?;

    // Services
    process_resources(Api::<Service>::all(client.clone()), &rules, &Resource::Service, &levels, &category, &resource).await?;

    // Ingress
    process_resources(Api::<Ingress>::all(client.clone()), &rules, &Resource::Ingress, &levels, &category, &resource).await?;

    // ConfigMap
    process_resources(Api::<ConfigMap>::all(client.clone()), &rules, &Resource::ConfigMap, &levels, &category, &resource).await?;

    // HorizontalPodAutoscaler
    process_resources(Api::<HorizontalPodAutoscaler>::all(client.clone()), &rules, &Resource::HorizontalPodAutoscaler, &levels, &category, &resource).await?;

    // Secret
    process_resources(Api::<Secret>::all(client.clone()), &rules, &Resource::Secret, &levels, &category, &resource).await?;

    // ResourceQuota
    process_resources(Api::<ResourceQuota>::all(client.clone()), &rules, &Resource::ResourceQuota, &levels, &category, &resource).await?;

    // StatefulSet
    process_resources(Api::<StatefulSet>::all(client.clone()), &rules, &Resource::StatefulSet, &levels, &category, &resource).await?;

    // DaemonSet
    process_resources(Api::<DaemonSet>::all(client.clone()), &rules, &Resource::DaemonSet, &levels, &category, &resource).await?;

    // Job
    process_resources(Api::<Job>::all(client.clone()), &rules, &Resource::Job, &levels, &category, &resource).await?;

    // CronJob
    process_resources(Api::<CronJob>::all(client.clone()), &rules, &Resource::CronJob, &levels, &category, &resource).await?;

    // LimitRange
    process_resources(Api::<LimitRange>::all(client.clone()), &rules, &Resource::LimitRange, &levels, &category, &resource).await?;

    // VerticalPodAutoscaler
    //process_resources(Api::<VerticalPodAutoscaler>::all(client.clone()), &rules, &Resource::VerticalPodAutoscaler, &levels, &category, &resource).await?;

    // ServiceAccount
    process_resources(Api::<ServiceAccount>::all(client.clone()), &rules, &Resource::ServiceAccount, &levels, &category, &resource).await?;

    // NetworkPolicy
    process_resources(Api::<NetworkPolicy>::all(client.clone()), &rules, &Resource::NetworkPolicy, &levels, &category, &resource).await?;

    // PriorityClass
    process_resources(Api::<PriorityClass>::all(client.clone()), &rules, &Resource::PriorityClass, &levels, &category, &resource).await?;

    // PersistentVolumeClaim
    process_resources(Api::<PersistentVolumeClaim>::all(client.clone()), &rules, &Resource::PersistentVolumeClaim, &levels, &category, &resource).await?;

    // PersistentVolume
    process_resources(Api::<PersistentVolume>::all(client.clone()), &rules, &Resource::PersistentVolume, &levels, &category, &resource).await?;

    // IngressClass
    process_resources(Api::<IngressClass>::all(client.clone()), &rules, &Resource::IngressClass, &levels, &category, &resource).await?;

    // PodDisruptionBudget
    process_resources(Api::<PodDisruptionBudget>::all(client.clone()), &rules, &Resource::PodDisruptionBudget, &levels, &category, &resource).await?;

    // CustomResourceDefinition
    process_resources(Api::<CustomResourceDefinition>::all(client.clone()), &rules, &Resource::CustomResourceDefinition, &levels, &category, &resource).await?;

    // Endpoints
    process_resources(Api::<Endpoints>::all(client.clone()), &rules, &Resource::Endpoints, &levels, &category, &resource).await?;

    // EndpointSlice
    process_resources(Api::<EndpointSlice>::all(client.clone()), &rules, &Resource::EndpointSlice, &levels, &category, &resource).await?;

    // Namespace
    process_resources(Api::<Namespace>::all(client.clone()), &rules, &Resource::Namespace, &levels, &category, &resource).await?;

    Ok(())
}

async fn process_resources<K>(api: Api<K>, rules: &Vec<K8sRule>, resource: &Resource, 
                              levels: &Vec<Severity>, select_category: &Option<Category>,
                              select_resource: &Option<Resource>) -> anyhow::Result<()>
where
    K: kube::Resource + serde::de::DeserializeOwned + Clone + std::fmt::Debug + Serialize + Send + Sync + 'static,
{
    if select_resource.as_ref().map_or(true, |r| r == resource) {
        for item in api.list(&Default::default()).await? {
            let json = to_value(&item)?;
            run_rules(
                &rules,
                resource,
                &json,
                item.name_any().as_str(),
                &levels,
                select_category
            );
        }
    }

    Ok(())
}

fn run_rules(rules: &[K8sRule], resource_type: &Resource, json: &Value, name: &str, levels: &Vec<Severity>,
             select_category: &Option<Category>) {
    println!("Resource Type: {}", resource_type.to_string().bright_white().bold());

    for rule in rules.iter().filter(|r| r.resource.to_string() == resource_type.to_string()) {
        if select_category.as_ref().map_or(true, |c| c == &rule.category) {
            if levels.is_empty() || levels.contains(&rule.severity) {
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