use clap::ValueEnum;
use serde::Deserialize;
use serde_json::Value;
use strum_macros::{Display};

#[derive(Debug, Deserialize, Display, PartialEq, Eq, ValueEnum, Clone)]
pub enum Severity {
    Information,
    Warning,
    Error,
    Critical
}

impl Severity {
    pub fn included_levels(self) -> Vec<Severity> {
        use Severity::*;
        match self {
            Information => vec![Information, Warning, Error, Critical],
            Warning     => vec![Warning, Error, Critical],
            Error       => vec![Error, Critical],
            Critical    => vec![Critical],
        }
    }
}

#[derive(Debug, Deserialize, Display, PartialEq, Eq, ValueEnum, Clone)]
pub enum Category {
    Availability,
    Configuration,
    Networking,
    Security,
    Resources,
    Operational,
    Reliability,
    Scalability,
    Performance,
    Governance,
    Storage,
    Scheduling,
    ResourceGovernance
}

#[derive(Debug, Deserialize, Display, PartialEq, Eq, ValueEnum, Clone)]
pub enum Resource {
    Service,
    Deployment,
    Pod,
    Ingress,
    ConfigMap,
    HorizontalPodAutoscaler,
    Secret,
    ResourceQuota,
    StatefulSet,
    DaemonSet,
    Job,
    CronJob,
    LimitRange,
    VerticalPodAutoscaler,
    ServiceAccount,
    NetworkPolicy,
    PriorityClass,
    PersistentVolumeClaim,
    PersistentVolume,
    IngressClass,
    PodDisruptionBudget,
    CustomResourceDefinition,
    Endpoints,
    EndpointSlice,
    Namespace
}


#[derive(Debug, Deserialize)]
pub struct K8sRule {
    pub name: String,
    pub description: String,
    pub resource: Resource,
    pub jsonpath: String,
    pub operator: String,
    pub value: Option<Value>,
    pub category: Category,
    pub severity: Severity,
}
