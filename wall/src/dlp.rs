use regex::{NoExpand, Regex};
use serde_json::Value;

use crate::policy::Policy;

#[derive(Clone, Copy, PartialEq)]
pub enum Action {
    Redact,
    Block,
}

struct Rule {
    name: String,
    re: Regex,
    action: Action,
    replacement: String,
}

pub struct Dlp {
    pub enabled: bool,
    rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Hit {
    pub rule: String,
    pub block: bool,
    pub count: usize,
}

// Built-in detectors. Conservative — biased to low false positives. 
// Returns (pattern, default replacement). lallerlavish
fn builtin(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match name {
        "aws_key" => (r"AKIA[0-9A-Z]{16}", "<AWS-KEY-REDACTED>"),
        "private_key" => (
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",
            "<PRIVATE-KEY-REDACTED>",
        ),
        "jwt" => (
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "<JWT-REDACTED>",
        ),
        "github_pat" => (r"gh[pousr]_[A-Za-z0-9]{36,}", "<GITHUB-PAT-REDACTED>"),
        "slack_token" => (r"xox[baprs]-[A-Za-z0-9-]{10,}", "<SLACK-TOKEN-REDACTED>"),
        "email" => (
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "<EMAIL-REDACTED>",
        ),
        _ => return None,
    })
}

impl Dlp {
    pub fn from_policy(p: &Policy) -> Self {
        let mut rules = Vec::new();
        if p.dlp.enabled {
            for name in &p.dlp.builtins {
                match builtin(name) {
                    Some((pat, repl)) => match Regex::new(pat) {
                        Ok(re) => rules.push(Rule {
                            name: name.to_string(),
                            re,
                            action: Action::Redact,
                            replacement: repl.to_string(),
                        }),
                        Err(e) => eprintln!("wall: bad builtin dlp rule {name}: {e}"),
                    },
                    None => eprintln!("wall: unknown dlp builtin: {name}"),
                }
            }
            for r in &p.dlp.rules {
                let action = match r.action.as_deref() {
                    Some("block") => Action::Block,
                    _ => Action::Redact,
                };
                let replacement = r
                    .replacement
                    .clone()
                    .unwrap_or_else(|| format!("<{}-REDACTED>", r.name.to_uppercase()));
                match Regex::new(&r.pattern) {
                    Ok(re) => rules.push(Rule {
                        name: r.name.clone(),
                        re,
                        action,
                        replacement,
                    }),
                    Err(e) => eprintln!("wall: bad dlp rule {}: {e}", r.name),
                }
            }
        }
        Dlp {
            enabled: p.dlp.enabled && !rules.is_empty(),
            rules,
        }
    }

    // Walk a parsed JSON-RPC message, redacting string values in place. 
    // Only scans inside `result` / `params` / `error`; never the envelope 
    // (`jsonrpc` / `id` / `method`). Caller drops the message if any hit 
    // has `block == true`. lallerlavish
    pub fn scan(&self, msg: &mut Value) -> Vec<Hit> {
        let mut hits = Vec::new();
        if self.enabled {
            self.walk(msg, &mut hits, false);
        }
        hits
    }

    // Fallback for lines that don't parse as JSON — a server can't dodge 
    // DLP by emitting malformed framing. Scans the raw text. lallerlavish
    pub fn scan_raw(&self, s: &mut String) -> Vec<Hit> {
        let mut hits = Vec::new();
        if !self.enabled {
            return hits;
        }
        for rule in &self.rules {
            let n = rule.re.find_iter(s).count();
            if n == 0 {
                continue;
            }
            if rule.action == Action::Redact {
                *s = rule.re.replace_all(s, NoExpand(&rule.replacement)).into_owned();
            }
            record(&mut hits, &rule.name, rule.action == Action::Block, n);
        }
        hits
    }

    fn walk(&self, v: &mut Value, hits: &mut Vec<Hit>, in_payload: bool) {
        match v {
            Value::String(s) => {
                if !in_payload {
                    return;
                }
                for rule in &self.rules {
                    let n = rule.re.find_iter(s).count();
                    if n == 0 {
                        continue;
                    }
                    if rule.action == Action::Redact {
                        *s = rule.re.replace_all(s, NoExpand(&rule.replacement)).into_owned();
                    }
                    record(hits, &rule.name, rule.action == Action::Block, n);
                }
            }
            Value::Array(a) => {
                for x in a {
                    self.walk(x, hits, in_payload);
                }
            }
            Value::Object(o) => {
                for (k, val) in o.iter_mut() {
                    let enter =
                        in_payload || matches!(k.as_str(), "result" | "params" | "error");
                    self.walk(val, hits, enter);
                }
            }
            _ => {}
        }
    }
}

fn record(hits: &mut Vec<Hit>, name: &str, block: bool, n: usize) {
    if let Some(h) = hits.iter_mut().find(|h| h.rule == name) {
        h.count += n;
        h.block |= block;
    } else {
        hits.push(Hit {
            rule: name.to_string(),
            block,
            count: n,
        });
    }
}

// JSON-RPC error to send in place of a blocked response (preserves `id`). lallerlavish
pub fn block_response(orig: &Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": orig.get("id").cloned().unwrap_or(Value::Null),
        "error": {
            "code": -32001,
            "message": "blocked by wall DLP: response contained disallowed data"
        }
    })
}