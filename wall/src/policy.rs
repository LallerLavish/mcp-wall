use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Tools {
    // action for a tool with no explicit rule: "allow" | "ask" | "block"
    #[serde(default = "default_tool_action")]
    pub default: String,
    // per-tool overrides
    #[serde(default)]
    pub rules: HashMap<String, String>,
}

impl Default for Tools {
    fn default() -> Self {
        Tools { default: "allow".into(), rules: HashMap::new() }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Network {
    // Allowed egress destinations: IPs, CIDRs, or hostnames.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Dlp {
    #[serde(default)] pub enabled: bool,
    #[serde(default)] pub builtins: Vec<String>,
    #[serde(default, rename = "rule")] pub rules: Vec<DlpRule>,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DlpRule {
    pub name: String,
    pub pattern: String,
    #[serde(default)] pub action: Option<String>,      // "redact" (default) | "block"
    #[serde(default)] pub replacement: Option<String>,
}


#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]               
    pub tools: Tools, 
    #[serde(default)] 
    pub dlp: Dlp,
}

pub fn apply_landlock(policy: &Policy) -> Result<(), Box<dyn std::error::Error>> {
    let abi = ABI::V1;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?  //"I'm governing ALL filesystem rights" lallerlavish
        .create()?; //build the ruleset (a kernel object) lallerlavish
    for p in &policy.read {
        match PathFd::new(p) {
            Ok(fd) => ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))?,
            Err(e) => eprintln!("warden: skipping read path '{p}': {e}"),
        }
    }
    for p in &policy.write {
        match PathFd::new(p) {
            Ok(fd) => ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?,
            Err(e) => eprintln!("warden: skipping write path '{p}': {e}"),
        }
    }
    ruleset.restrict_self()?;
    Ok(())
}

pub fn load(path: &str) -> Policy {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("warden: cannot read policy {}: {}", path, e);
        std::process::exit(2);
    });
    // will going to save the policy file in the policy struct to use at run time lallerlavish
    toml::from_str(&s).unwrap_or_else(|e| {
        eprintln!("warden: invalid policy TOML: {}", e);
        std::process::exit(2);
    })
}

fn default_tool_action() -> String { "allow".into() }