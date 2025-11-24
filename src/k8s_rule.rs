use serde::Deserialize;
use serde_json::Value;
use strum_macros::{Display};


#[derive(Debug, Deserialize, Display)]
pub enum Severity {
    Information,
    Warning,
    Error
}

#[derive(Debug, Deserialize)]
pub struct K8sRule {
    pub name: String,
    pub description: String,
    pub resource: String,
    pub jsonpath: String,
    pub operator: String,
    pub value: Value,
    pub category: String,
    pub severity: Severity,
}