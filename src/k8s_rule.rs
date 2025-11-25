use serde::Deserialize;
use serde_json::Value;
use strum_macros::{Display};


#[derive(Debug, Deserialize, Display)]
pub enum Severity {
    Information,
    Warning,
    Error,
    Critical
}

#[derive(Debug, Deserialize, Display)]
pub enum Category {
    Availability,
    Configuration,
    Networking,
    Security,
    Resources,
    Operational,
    Reliability,
    Scalability,
    Performance
}

#[derive(Debug, Deserialize, Display)]
pub enum Resource {
    Service,
    Deployment,
    Pod,
    Ingress,
    ConfigMap,
    HorizontalPodAutoscaler
}


#[derive(Debug, Deserialize)]
pub struct K8sRule {
    pub name: String,
    pub description: String,
    pub resource: Resource,
    pub jsonpath: String,
    pub operator: String,
    pub value: Value,
    pub category: Category,
    pub severity: Severity,
}