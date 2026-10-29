//! Firewall rule specs: the value `--rule`, `--add-rule` and `--remove-rule`
//! take on `role` and `tag` create/edit, and the JSON rule it becomes.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail};
use serde_json::{Value, json};

use super::hosts::parse_tag;
use crate::ids::validate_id;

/// The grammar, shown as the flags' long help.
pub const RULE_SPEC_HELP: &str = "\
A firewall rule: PROTO[/PORTS][,from=ROLE_ID][,tags=KEY:VALUE[+KEY:VALUE…]][,desc=TEXT]

PROTO is any, tcp, udp or icmp. PORTS is one port (22) or a range (8000-9000); \
leave it off to allow every port (icmp takes none). from= allows only hosts \
with that role and tags= only hosts carrying every listed tag; leave both off \
to allow all hosts. desc= must come last and may contain commas.

Examples:
  tcp/22
  tcp/443,desc=https from anywhere
  udp/53,from=role-ABC,tags=env:prod+site:hou,desc=dns";

/// Parse one rule spec into the API's `FirewallRule` object, with every
/// field present: `allowedRoleID` and `allowedTags` are `null` when the rule
/// allows all hosts, `portRange` is `null` for every port.
pub fn parse_rule_spec(spec: &str) -> anyhow::Result<Value> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("rule must not be empty");
    }
    let (head, mut rest) = match spec.split_once(',') {
        Some((head, rest)) => (head.trim(), rest.trim_start()),
        None => (spec, ""),
    };
    let (proto, ports) = match head.split_once('/') {
        Some((proto, ports)) => (proto.trim(), Some(ports.trim())),
        None => (head, None),
    };
    let protocol = match proto.to_ascii_uppercase().as_str() {
        p @ ("ANY" | "TCP" | "UDP" | "ICMP") => p.to_string(),
        _ => bail!("protocol {proto:?} is not any, tcp, udp or icmp"),
    };
    let port_range = match ports {
        None => Value::Null,
        Some("") => bail!("ports after / must not be empty"),
        Some(ports) => parse_ports(ports)?,
    };
    if protocol == "ICMP" && !port_range.is_null() {
        bail!("an icmp rule takes no ports");
    }

    let mut role = Value::Null;
    let mut tags = Value::Null;
    let mut description = String::new();
    let mut seen: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let (key, after) = rest
            .split_once('=')
            .ok_or_else(|| anyhow!("expected from=, tags= or desc=, got {rest:?}"))?;
        let key = key.trim();
        if seen.iter().any(|s| s == key) {
            bail!("{key}= given twice");
        }
        // desc= runs to the end of the spec; the others end at the next comma.
        let (value, next) = if key == "desc" {
            (after.trim(), "")
        } else {
            match after.split_once(',') {
                Some((value, next)) => (value.trim(), next.trim_start()),
                None => (after.trim(), ""),
            }
        };
        if value.is_empty() {
            bail!("{key}= must not be empty");
        }
        match key {
            "from" => {
                validate_id("role", value).map_err(|e| anyhow!("from=: {e}"))?;
                role = json!(value);
            }
            "tags" => {
                let mut list: Vec<String> = Vec::new();
                for tag in value.split('+') {
                    let tag = tag.trim();
                    parse_tag(tag).map_err(|e| anyhow!("tags=: {e}"))?;
                    if !list.iter().any(|t| t == tag) {
                        list.push(tag.to_string());
                    }
                }
                tags = json!(list);
            }
            "desc" => {
                if value.chars().count() > 255 {
                    bail!("desc= must be at most 255 characters");
                }
                description = value.to_string();
            }
            other => bail!("unknown rule field {other:?}; expected from=, tags= or desc="),
        }
        seen.push(key.to_string());
        rest = next;
    }

    Ok(json!({
        "protocol": protocol,
        "portRange": port_range,
        "allowedRoleID": role,
        "allowedTags": tags,
        "description": description,
    }))
}

/// `N` or `N-M` as the API's `{from, to}`, both in 1..=65535 with
/// `from <= to`.
fn parse_ports(ports: &str) -> anyhow::Result<Value> {
    let (from, to) = match ports.split_once('-') {
        Some((from, to)) => (from.trim(), to.trim()),
        None => (ports, ports),
    };
    let port = |p: &str| -> anyhow::Result<u16> {
        let n: u32 = p
            .parse()
            .map_err(|_| anyhow!("port {p:?} is not a number"))?;
        u16::try_from(n)
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| anyhow!("port {n} is not between 1 and 65535"))
    };
    let (from, to) = (port(from)?, port(to)?);
    if from > to {
        bail!("port range {from}-{to} runs backwards");
    }
    Ok(json!({ "from": from, "to": to }))
}

/// Whether two rules allow the same traffic: same protocol, ports, and
/// allowed role and tags. The description is a label, so it doesn't count.
pub fn rules_match(a: &Value, b: &Value) -> bool {
    let protocol = |r: &Value| r["protocol"].as_str().map(str::to_ascii_uppercase);
    let ports = |r: &Value| {
        let range = &r["portRange"];
        (!range.is_null()).then(|| (range["from"].as_u64(), range["to"].as_u64()))
    };
    let role = |r: &Value| r["allowedRoleID"].as_str().map(str::to_string);
    let tags = |r: &Value| -> BTreeSet<String> {
        r["allowedTags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    protocol(a) == protocol(b) && ports(a) == ports(b) && role(a) == role(b) && tags(a) == tags(b)
}

/// The rule edits `role edit` and `tag edit` take, already parsed.
pub struct RuleEdits {
    pub clear: bool,
    pub remove: Vec<Value>,
    pub add: Vec<Value>,
}

/// Apply edits to a rule list: clear, then remove every rule that
/// [`rules_match`] a `remove` entry, then add — an `add` that matches an
/// existing rule replaces it (so re-adding a rule updates its description)
/// rather than duplicating it. Returns the new list and the indices into
/// `remove` that matched nothing, for the caller to warn about.
pub fn apply_rule_edits(current: &[Value], edits: &RuleEdits) -> (Vec<Value>, Vec<usize>) {
    let mut rules: Vec<Value> = if edits.clear {
        Vec::new()
    } else {
        current.to_vec()
    };
    let mut unmatched = Vec::new();
    for (i, gone) in edits.remove.iter().enumerate() {
        let before = rules.len();
        rules.retain(|r| !rules_match(r, gone));
        if rules.len() == before {
            unmatched.push(i);
        }
    }
    for new in &edits.add {
        match rules.iter_mut().find(|r| rules_match(r, new)) {
            Some(slot) => *slot = new.clone(),
            None => rules.push(new.clone()),
        }
    }
    (rules, unmatched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_protocol_allows_every_port_from_every_host() {
        assert_eq!(
            parse_rule_spec("any").unwrap(),
            json!({"protocol": "ANY", "portRange": null, "allowedRoleID": null,
                   "allowedTags": null, "description": ""})
        );
    }

    #[test]
    fn a_full_spec_fills_every_field() {
        assert_eq!(
            parse_rule_spec(" udp/53 , from=role-ABC, tags=env:prod+site:hou , desc=dns, primary ")
                .unwrap(),
            json!({"protocol": "UDP", "portRange": {"from": 53, "to": 53},
                   "allowedRoleID": "role-ABC", "allowedTags": ["env:prod", "site:hou"],
                   "description": "dns, primary"})
        );
    }

    #[test]
    fn a_port_range_and_case_insensitive_protocol() {
        let rule = parse_rule_spec("Tcp/8000-9000").unwrap();
        assert_eq!(rule["protocol"], "TCP");
        assert_eq!(rule["portRange"], json!({"from": 8000, "to": 9000}));
    }

    #[test]
    fn repeated_tags_collapse() {
        let rule = parse_rule_spec("tcp,tags=a:b+a:b").unwrap();
        assert_eq!(rule["allowedTags"], json!(["a:b"]));
    }

    #[test]
    fn bad_specs_say_what_is_wrong() {
        for (spec, want) in [
            ("", "must not be empty"),
            ("sctp/22", "not any, tcp, udp or icmp"),
            ("tcp/", "ports after / must not be empty"),
            ("tcp/0", "not between 1 and 65535"),
            ("tcp/70000", "not between 1 and 65535"),
            ("tcp/22x", "is not a number"),
            ("tcp/90-80", "runs backwards"),
            ("icmp/8", "takes no ports"),
            ("tcp,from=", "from= must not be empty"),
            (
                "tcp,from=role/x",
                "from=: role id contains invalid character '/'",
            ),
            ("tcp,tags=nocolon", "tags=: "),
            ("tcp,port=22", "unknown rule field \"port\""),
            ("tcp,from=role-A,from=role-B", "from= given twice"),
            ("tcp,junk", "expected from=, tags= or desc="),
        ] {
            let err = parse_rule_spec(spec).unwrap_err().to_string();
            assert!(err.contains(want), "{spec:?}: {err}");
        }
        let long = format!("tcp,desc={}", "x".repeat(256));
        assert!(parse_rule_spec(&long).is_err());
    }

    #[test]
    fn matching_ignores_description_tag_order_and_protocol_case() {
        let a = json!({"protocol": "tcp", "portRange": {"from": 22, "to": 22},
                       "allowedRoleID": null, "allowedTags": ["b:1", "a:1"], "description": "x"});
        let b = parse_rule_spec("TCP/22,tags=a:1+b:1,desc=y").unwrap();
        assert!(rules_match(&a, &b));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/22,tags=a:1").unwrap()
        ));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/23,tags=a:1+b:1").unwrap()
        ));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/22,from=role-A,tags=a:1+b:1").unwrap()
        ));
    }

    #[test]
    fn edits_clear_remove_replace_and_append() {
        let current = vec![
            parse_rule_spec("tcp/22,desc=ssh").unwrap(),
            parse_rule_spec("tcp/443").unwrap(),
        ];
        let edits = RuleEdits {
            clear: false,
            remove: vec![
                parse_rule_spec("tcp/443").unwrap(),
                parse_rule_spec("udp/53").unwrap(),
            ],
            add: vec![
                parse_rule_spec("tcp/22,desc=ssh from anywhere").unwrap(),
                parse_rule_spec("icmp").unwrap(),
            ],
        };
        let (rules, unmatched) = apply_rule_edits(&current, &edits);
        assert_eq!(unmatched, [1]);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["description"], "ssh from anywhere");
        assert_eq!(rules[1]["protocol"], "ICMP");

        let (rules, _) = apply_rule_edits(
            &current,
            &RuleEdits {
                clear: true,
                remove: vec![],
                add: vec![],
            },
        );
        assert!(rules.is_empty());
    }
}
