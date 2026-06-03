use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use serde_json::Value;
use crate::dlp::Dlp;

use crate::log::{log_event,log_line, Log};
pub fn pipe_and_log<R: Read, W: Write>(
    src: R,
    mut dst: W,
    direction_tag: &'static str,
    log: Log,
    dlp: Arc<Dlp>,
) -> io::Result<()> {
    let mut reader = BufReader::new(src);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }

        // v2.5 DLP — scan/redact/block on the egress path before it leaves. lallerlavish
        let out: String = if !dlp.enabled {
            line.clone()
        } else if let Ok(mut msg) = serde_json::from_str::<Value>(line.trim_end()) {
            let hits = dlp.scan(&mut msg);
            for h in &hits {
                log_event(&log, "dlp", serde_json::json!({
                    "direction": direction_tag, "rule": h.rule,
                    "action": if h.block { "block" } else { "redact" }, "count": h.count,
                }));
            }
            if hits.iter().any(|h| h.block) {
                format!("{}\n", crate::dlp::block_response(&msg))
            } else if hits.is_empty() {
                line.clone()
            } else {
                format!("{msg}\n")
            }
        } else {
            let mut raw = line.clone();
            let hits = dlp.scan_raw(&mut raw);
            for h in &hits {
                log_event(&log, "dlp", serde_json::json!({
                    "direction": direction_tag, "rule": h.rule,
                    "action": if h.block { "block" } else { "redact" }, "count": h.count,
                }));
            }
            if hits.iter().any(|h| h.block) { String::new() } else { raw }
        };

        if out.is_empty() {
            continue; // blocked — emit nothing downstream lallerlavish
        }
        log_line(&log, direction_tag, &out); // log the forwarded (redacted) line lallerlavish
        if let Err(e) = dst.write_all(out.as_bytes()) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e);
        }
        dst.flush()?;
    }
    Ok(())
}



pub type Decisions = Arc<DecisionStore>;

pub struct DecisionStore {
    map: Mutex<HashMap<String, String>>,
    path: Option<PathBuf>,
}

impl DecisionStore {
    // Load persisted "always" decisions from the sidecar (if it exists). lallerlavish
    pub fn load(path: Option<PathBuf>) -> Decisions {
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<HashMap<String, String>>(&s).ok())
            .unwrap_or_default();
        Arc::new(DecisionStore { map: Mutex::new(map), path })
    }
    fn get(&self, tool: &str) -> Option<String> {
        self.map.lock().unwrap().get(tool).cloned()
    }
    // Record an "always" decision and flush the whole map to the sidecar. lallerlavish
    fn remember(&self, tool: &str, action: &str) {
        let mut m = self.map.lock().unwrap();
        m.insert(tool.to_string(), action.to_string());
        if let Some(p) = &self.path {
            if let Ok(json) = serde_json::to_string_pretty(&*m) {
                let _ = std::fs::write(p, json);
            }
        }
    }
}

pub fn pipe_gate_and_log<R: Read, W: Write>(
    src: R,
    mut child_in: W,
    log: Log,
    tools_default: String,
    tools_rules: HashMap<String, String>,
    decisions: Decisions,
) -> io::Result<()> {
    let mut reader = BufReader::new(src);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        log_line(&log, "client->server", &line);

        // gate tools/call before forwarding lallerlavish
        if let Ok(v) = serde_json::from_str::<Value>(line.trim_end()) {
            if v.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                let tool = v["params"]["name"].as_str().unwrap_or("").to_string();
                let id = v.get("id").cloned().unwrap_or(Value::Null);
                let action = decide(&tool, &tools_default, &tools_rules, &decisions);
                log_event(&log, "tool.call", serde_json::json!({"tool": tool, "decision": action}));
                if action == "block" {
                    write_block_response(&log, &id, &tool);   // pass log
                    log_event(&log, "tool.call", serde_json::json!({"tool": tool, "decision": "block"}));
                    continue;
                }
            }
        }

        if let Err(e) = child_in.write_all(line.as_bytes()) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e);
        }
        child_in.flush()?;
    }
    Ok(())
}

fn decide(
    tool: &str,
    default: &str,
    rules: &HashMap<String, String>,
    decisions: &Decisions,
) -> String {
    if let Some(d) = decisions.get(tool) {
        return d;
    }
    match rules.get(tool).map(|s| s.as_str()).unwrap_or(default) {
        "allow" => "allow".into(),
        "block" => "block".into(),
        "ask" => prompt(tool, decisions),
        _ => "allow".into(),
    }
}

fn prompt(tool: &str, decisions: &Decisions) -> String {
    // controlling terminal, NOT the MCP pipe — so the prompt never corrupts stdout lallerlavish
    let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        eprintln!("[warden] no tty; auto-allowing '{tool}' (set default=\"block\" for strict)");
        return "allow".into();
    };
    let _ = write!(
        tty,
        "\n[warden] server wants tool '{tool}'  [a]llow once / [A]lways / [b]lock once / [B] always-block: "
    );
    let _ = tty.flush();
    let mut ans = String::new();
    if BufReader::new(tty).read_line(&mut ans).is_err() {
        return "block".into();
    }
    match ans.trim() {
        "a" => "allow".into(),
        "A" => { decisions.remember(tool, "allow"); "allow".into() }
        "B" => { decisions.remember(tool, "block"); "block".into() }
        _ => "block".into(), // "b" or anything else = block this one lallerlavish
    }
}

fn write_block_response(log: &Log, id: &Value, tool: &str) {
    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32000, "message": format!("warden: tool '{tool}' blocked by policy") }
    });
    log_line(log, "server->client", &resp.to_string());   // audit the injected response lallerlavish
    let out = io::stdout();
    let mut h = out.lock();
    let _ = writeln!(h, "{resp}");
    let _ = h.flush();
}