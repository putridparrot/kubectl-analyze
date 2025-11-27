use std::{env, fs};
use std::fmt::format;
use serde_json::Value;
//use jsonschema::{JSONSchema, Draft};
use std::path::Path;
use crate::configuration::Configuration;

pub fn update_rules() -> anyhow::Result<()> {
    // - Linux: ~/.config/kubectl-analyze/rules.json
    // - macOS: ~/Library/Application Support/kubectl-analyze/rules.json
    // - Windows: C:\Users\<User>\AppData\Roaming\kubectl-analyze\rules.json

    // let config_dir = dirs::config_dir()
    //     .unwrap()
    //     .join("kubectl-rules");

    let exe = env::current_exe()?;
    let exe_dir = exe.parent().unwrap();
    let config_dir = exe_dir;

    fs::create_dir_all(&config_dir)?;
    let rules_path = config_dir.join(Configuration::RULES_FILE);
    let backup_path = config_dir.join(format!("{}.bak", Configuration::RULES_FILE));

    let url = format!("https://raw.githubusercontent.com/putridparrot/kubectl-analyze/main/{}", Configuration::RULES_FILE);
    let remote = reqwest::blocking::get(url)?.text()?;

    if rules_path.exists() {
        fs::copy(&rules_path, &backup_path)?;
    }

    let candidate: Value = match serde_json::from_str(&remote) {
        Ok(val) => val,
        Err(e) => {
            println!("Invalid JSON: {e}");
            rollback(&backup_path, &rules_path)?;
            return Ok(());
        }
    };

    // Load schema
    // let schema_str = include_str!("rules_schema.json");
    // let schema_json: Value = serde_json::from_str(schema_str)?;
    // let compiled = JSONSchema::compile(&schema_json)?;
    //
    // // Validate against schema
    // if let Err(errors) = compiled.validate(&candidate) {
    //     println!("Schema validation failed:");
    //     for err in errors {
    //         println!(" - {err}");
    //     }
    //     rollback(&backup_path, &rules_path)?;
    // } else {
    //     fs::write(&rules_path, remote)?;
    //     println!("Updated rules.json. Backup saved at {:?}", backup_path);
    // }

    Ok(())
}

fn rollback(backup: &Path, target: &Path) -> anyhow::Result<()> {
    if backup.exists() {
        fs::copy(backup, target)?;
        println!("Rolled back to the previous rules file from backup.");
    } else {
        println!("No backup available, rules file left unchanged.");
    }
    Ok(())
}
