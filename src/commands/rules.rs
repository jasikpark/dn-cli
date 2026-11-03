//! Firewall rule specs: the value `--rule`, `--add-rule` and `--remove-rule`
//! take on `role` and `tag` create/edit, and the JSON rule it becomes.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail};
use serde_json::{Value, json};

use super::firewall::rule_ports;
use super::hosts::parse_tag;
use crate::ids::validate_id;

/// The grammar, shown as the flags' long help.
pub const RULE_SPEC_HELP: &str = "\
A firewall rule: PROTO[/PORTS][,from=ROLE_ID][,tag=KEY:VALUE]...[,desc=TEXT]

PROTO is any, tcp, udp or icmp. PORTS is one port (22) or a range (8000-9000); \
leave it off to allow every port (icmp takes none). from= allows only hosts \
with that role; tag= (repeatable) only hosts carrying every tag given; leave \
both off to allow all hosts. desc= must come last and may contain commas. A \
tag whose value contains a comma can't be written in a spec.

Examples:
  tcp/22
  tcp/443,desc=https from anywhere
  udp/53,from=role-B2RPGZ2TEPSZO5EGJJAX5LNN7M,tag=env:prod,tag=site:hou,desc=dns";

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
    let mut tags: Vec<String> = Vec::new();
    let mut description = String::new();
    let mut seen: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let (key, after) = rest
            .split_once('=')
            .ok_or_else(|| anyhow!("expected from=, tag= or desc=, got {rest:?}"))?;
        let key = key.trim();
        if key != "tag" && seen.iter().any(|s| s == key) {
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
            "tag" => {
                parse_tag(value).map_err(|e| anyhow!("tag=: {e}"))?;
                if !tags.iter().any(|t| t == value) {
                    tags.push(value.to_string());
                }
            }
            "desc" => {
                if value.chars().count() > 255 {
                    bail!("desc= must be at most 255 characters");
                }
                description = value.to_string();
            }
            other => bail!("unknown rule field {other:?}; expected from=, tag= or desc="),
        }
        seen.push(key.to_string());
        rest = next;
    }

    Ok(json!({
        "protocol": protocol,
        "portRange": port_range,
        "allowedRoleID": role,
        "allowedTags": if tags.is_empty() { Value::Null } else { json!(tags) },
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
/// Ports compare the way the `role get` table reads them ([`rule_ports`]):
/// a null range, a range starting at 0, and any range on an ICMP rule all
/// mean every port, so `--remove-rule any` finds an allow-everything rule
/// the API stored as `{from: 0, to: 0}`.
pub fn rules_match(a: &Value, b: &Value) -> bool {
    let protocol = |r: &Value| r["protocol"].as_str().map(str::to_ascii_uppercase);
    let ports = rule_ports;
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
#[derive(Debug)]
pub struct RuleEdits {
    pub clear: bool,
    pub remove: Vec<Value>,
    pub add: Vec<Value>,
}

/// Apply edits to a rule list: clear, then remove every rule that
/// [`rules_match`] a `remove` entry, then add. An `add` that matches an
/// existing rule keeps that rule as the API stored it (same traffic,
/// whatever encoding) and only changes its description when the spec's
/// differs, so re-adding an unchanged rule leaves the list untouched and
/// nothing is written. Returns the new list and the indices into `remove`
/// that matched nothing, for the caller to warn about.
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
            Some(existing) => {
                if existing["description"] != new["description"] {
                    existing["description"] = new["description"].clone();
                }
            }
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
            parse_rule_spec(
                " udp/53 , from=role-B2RPGZ2TEPSZO5EGJJAX5LNN7M, tag=env:prod, tag=site:hou , desc=dns, primary "
            )
            .unwrap(),
            json!({"protocol": "UDP", "portRange": {"from": 53, "to": 53},
                   "allowedRoleID": "role-B2RPGZ2TEPSZO5EGJJAX5LNN7M", "allowedTags": ["env:prod", "site:hou"],
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
    fn repeated_tags_collapse_and_plus_is_an_ordinary_character() {
        let rule = parse_rule_spec("tcp,tag=a:b,tag=a:b,tag=lang:c++").unwrap();
        assert_eq!(rule["allowedTags"], json!(["a:b", "lang:c++"]));
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
            ("tcp,tag=nocolon", "tag=: "),
            ("tcp,port=22", "unknown rule field \"port\""),
            (
                "tcp,from=role-6TZVMAEXCQB4WXWTY5XY6HG7DI,from=role-XFRJV7HNTRK3Z4GYR35WEG47UA",
                "from= given twice",
            ),
            ("tcp,junk", "expected from=, tag= or desc="),
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
        let b = parse_rule_spec("TCP/22,tag=a:1,tag=b:1,desc=y").unwrap();
        assert!(rules_match(&a, &b));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/22,tag=a:1").unwrap()
        ));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/23,tag=a:1,tag=b:1").unwrap()
        ));
        assert!(!rules_match(
            &a,
            &parse_rule_spec("tcp/22,from=role-6TZVMAEXCQB4WXWTY5XY6HG7DI,tag=a:1,tag=b:1")
                .unwrap()
        ));
    }

    #[test]
    fn a_zero_port_range_matches_an_any_port_spec() {
        // The API can store "every port" as {from: 0, to: 0}; the spec
        // grammar says it as no ports at all.
        let stored = json!({"protocol": "ANY", "portRange": {"from": 0, "to": 0},
                            "allowedRoleID": null, "allowedTags": null, "description": "open"});
        let spec = parse_rule_spec("any,desc=still open").unwrap();
        assert!(rules_match(&stored, &spec));
        assert!(!rules_match(
            &stored,
            &parse_rule_spec("any,from=role-6TZVMAEXCQB4WXWTY5XY6HG7DI").unwrap()
        ));

        // ICMP ignores ports entirely, however the API spelled them.
        let ping = json!({"protocol": "ICMP", "portRange": {"from": 8, "to": 8},
                          "allowedRoleID": null, "allowedTags": null, "description": ""});
        assert!(rules_match(&ping, &parse_rule_spec("icmp").unwrap()));

        // So removing finds it, and re-adding replaces rather than duplicates.
        let current = vec![stored.clone(), parse_rule_spec("tcp/22").unwrap()];
        let remove = RuleEdits {
            clear: false,
            remove: vec![spec.clone()],
            add: vec![],
        };
        let (rules, unmatched) = apply_rule_edits(&current, &remove);
        assert!(unmatched.is_empty());
        assert_eq!(rules, [parse_rule_spec("tcp/22").unwrap()]);
        let readd = RuleEdits {
            clear: false,
            remove: vec![],
            add: vec![spec.clone()],
        };
        let (rules, _) = apply_rule_edits(&current, &readd);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["description"], "still open");
        // The stored encoding is kept; only the description moved.
        assert_eq!(rules[0]["portRange"], json!({"from": 0, "to": 0}));
    }

    #[test]
    fn re_adding_an_unchanged_rule_leaves_the_list_as_stored() {
        let stored = json!({"protocol": "tcp", "portRange": {"from": 0, "to": 0},
                            "allowedRoleID": null, "allowedTags": ["b:1", "a:1"],
                            "description": "same", "futureField": true});
        let current = vec![stored.clone()];
        let edits = RuleEdits {
            clear: false,
            remove: vec![],
            add: vec![parse_rule_spec("TCP,tag=a:1,tag=b:1,desc=same").unwrap()],
        };
        let (rules, _) = apply_rule_edits(&current, &edits);
        assert_eq!(rules, current);
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

    mod props {
        use std::collections::BTreeSet;

        use proptest::prelude::*;

        use super::*;
        use crate::commands::firewall::compare_firewall_rules;

        /// A rule as the API might store it, including the encodings
        /// `rules_match` must see through: lower-case protocols, an
        /// every-port range written as null or `{from: 0, ...}`, ports on an
        /// ICMP rule, and an empty tag list beside a null one.
        fn api_rule() -> impl Strategy<Value = Value> {
            let protocol = prop::sample::select(vec!["ANY", "TCP", "UDP", "ICMP", "tcp", "icmp"]);
            let ports = prop_oneof![
                Just(Value::Null),
                Just(json!({"from": 0, "to": 0})),
                Just(json!({"from": 0, "to": 65535})),
                (1u16..4, 1u16..4).prop_map(|(a, b)| json!({"from": a.min(b), "to": a.max(b)})),
            ];
            let role = prop::option::of(prop::sample::select(vec!["role-A", "role-B"]));
            let tags = prop_oneof![
                Just(Value::Null),
                Just(json!([])),
                prop::collection::vec(prop::sample::select(vec!["env:prod", "site:hou"]), 1..3)
                    .prop_map(|t| json!(t)),
            ];
            let description = prop::sample::select(vec!["", "web", "dns"]);
            (protocol, ports, role, tags, description).prop_map(|(p, ports, role, tags, d)| {
                json!({"protocol": p, "portRange": ports, "allowedRoleID": role,
                       "allowedTags": tags, "description": d})
            })
        }

        fn edits() -> impl Strategy<Value = RuleEdits> {
            (
                any::<bool>(),
                prop::collection::vec(api_rule(), 0..4),
                prop::collection::vec(api_rule(), 0..4),
            )
                .prop_map(|(clear, remove, add)| RuleEdits { clear, remove, add })
        }

        /// The rules as a multiset, ignoring order.
        fn as_set(rules: &[Value]) -> Vec<String> {
            let mut set: Vec<String> = rules.iter().map(Value::to_string).collect();
            set.sort();
            set
        }

        /// A spec and the rule it should parse to, built from parts the
        /// grammar allows: any protocol case, a port or range (none on
        /// ICMP), a role id, tags (repeats collapse) and a description that
        /// may hold commas and `=`.
        fn spec_and_rule() -> impl Strategy<Value = (String, Value)> {
            let protocol = prop::sample::select(vec!["any", "TCP", "Udp", "icmp"]);
            let ports = prop::option::of((1u16..=65535, 1u16..=65535));
            let role = prop::option::of("[A-Za-z0-9_-]{1,32}");
            let tag = ("[^,:\\s\\p{Cc}]{1,20}", "[^,\\s\\p{Cc}]{1,50}")
                .prop_map(|(k, v)| format!("{k}:{v}"));
            let tags = prop::collection::vec(tag, 0..4);
            let description = prop::option::of("[^\\s\\p{Cc}]([^\\p{Cc}]{0,253}[^\\s\\p{Cc}])?");
            let separator = prop::sample::select(vec![",", ", ", " , "]);
            (protocol, ports, role, tags, description, any::<bool>(), separator).prop_map(
                |(protocol, ports, role, tags, description, role_last, sep)| {
                    let upper = protocol.to_ascii_uppercase();
                    let ports = ports
                        .filter(|_| upper != "ICMP")
                        .map(|(a, b)| (a.min(b), a.max(b)));
                    let mut head = protocol.to_string();
                    if let Some((from, to)) = ports {
                        head += &if from == to { format!("/{from}") } else { format!("/{from}-{to}") };
                    }
                    let mut fields: Vec<String> = tags.iter().map(|t| format!("tag={t}")).collect();
                    if let Some(role) = &role {
                        let at = if role_last { fields.len() } else { 0 };
                        fields.insert(at, format!("from={role}"));
                    }
                    if let Some(d) = &description {
                        fields.push(format!("desc={d}"));
                    }
                    let spec = std::iter::once(head).chain(fields).collect::<Vec<_>>().join(sep);

                    let mut unique: Vec<&String> = Vec::new();
                    for t in &tags {
                        if !unique.contains(&t) {
                            unique.push(t);
                        }
                    }
                    let rule = json!({
                        "protocol": upper,
                        "portRange": ports.map(|(from, to)| json!({"from": from, "to": to})),
                        "allowedRoleID": role,
                        "allowedTags": if unique.is_empty() { Value::Null } else { json!(unique) },
                        "description": description.unwrap_or_default(),
                    });
                    (spec, rule)
                },
            )
        }

        proptest! {
            #[test]
            fn rules_match_is_an_equivalence(a in api_rule(), b in api_rule(), c in api_rule()) {
                prop_assert!(rules_match(&a, &a));
                prop_assert_eq!(rules_match(&a, &b), rules_match(&b, &a));
                if rules_match(&a, &b) && rules_match(&b, &c) {
                    prop_assert!(rules_match(&a, &c));
                }
            }

            #[test]
            fn descriptions_never_affect_a_match(a in api_rule(), d in "\\PC{0,8}") {
                let mut relabelled = a.clone();
                relabelled["description"] = json!(d);
                prop_assert!(rules_match(&a, &relabelled));
            }

            #[test]
            fn edits_do_what_they_say(current in prop::collection::vec(api_rule(), 0..6), edits in edits()) {
                let start: Vec<Value> = if edits.clear { Vec::new() } else { current.clone() };
                let (rules, unmatched) = apply_rule_edits(&current, &edits);

                // Every added rule is there afterwards.
                for new in &edits.add {
                    prop_assert!(rules.iter().any(|r| rules_match(r, new)), "lost {}", new);
                }
                // A removed rule is gone unless an add brought it back.
                for gone in &edits.remove {
                    if !edits.add.iter().any(|a| rules_match(a, gone)) {
                        prop_assert!(!rules.iter().any(|r| rules_match(r, gone)), "kept {}", gone);
                    }
                }
                // Rules nobody named survive.
                for kept in start.iter().filter(|r| !edits.remove.iter().any(|g| rules_match(r, g))) {
                    prop_assert!(rules.iter().any(|r| rules_match(r, kept)), "dropped {}", kept);
                }
                // A remove is reported unmatched exactly when nothing was
                // left for it: it matched no rule to begin with, or an
                // earlier remove already took the same traffic.
                for (i, gone) in edits.remove.iter().enumerate() {
                    let had_match = start.iter().any(|r| rules_match(r, gone));
                    let taken_earlier = edits.remove[..i].iter().any(|g| rules_match(g, gone));
                    prop_assert_eq!(unmatched.contains(&i), !had_match || taken_earlier, "remove #{}", i);
                }
            }

            #[test]
            fn running_an_edit_twice_changes_nothing_more(
                current in prop::collection::vec(api_rule(), 0..6),
                edits in edits(),
            ) {
                let (once, _) = apply_rule_edits(&current, &edits);
                let (twice, _) = apply_rule_edits(&once, &edits);
                // A spec both removed and added moves to the end, so compare
                // as sets: the rules, not their order.
                prop_assert_eq!(as_set(&once), as_set(&twice));
            }

            #[test]
            fn re_adding_existing_rules_writes_nothing(current in prop::collection::vec(api_rule(), 0..6)) {
                let add: Vec<Value> = current.iter().step_by(2).cloned().collect();
                let edits = RuleEdits { clear: false, remove: Vec::new(), add };
                let (rules, unmatched) = apply_rule_edits(&current, &edits);
                // Only a matching rule's description may change; with the
                // same rules re-added, nothing does.
                let unchanged = current.iter().all(|r| {
                    current.iter().filter(|o| rules_match(o, r)).all(|o| o["description"] == r["description"])
                });
                if unchanged {
                    prop_assert_eq!(rules, current);
                }
                prop_assert!(unmatched.is_empty());
            }

            #[test]
            fn the_rule_order_is_a_total_order(a in api_rule(), b in api_rule(), c in api_rule()) {
                use std::cmp::Ordering::Greater;
                prop_assert_eq!(compare_firewall_rules(&a, &b), compare_firewall_rules(&b, &a).reverse());
                if compare_firewall_rules(&a, &b) != Greater && compare_firewall_rules(&b, &c) != Greater {
                    prop_assert_ne!(compare_firewall_rules(&a, &c), Greater);
                }
            }

            #[test]
            fn a_well_formed_spec_parses_to_its_rule((spec, rule) in spec_and_rule()) {
                prop_assert_eq!(parse_rule_spec(&spec).unwrap(), rule, "spec: {:?}", spec);
            }

            #[test]
            fn any_spec_either_fails_or_gives_a_valid_rule(
                parts in prop::collection::vec(
                    prop_oneof![
                        prop::sample::select(vec![
                            "tcp", "udp", "icmp", "any", "/", "-", ",", "=", "from", "tag", "desc",
                            ":", "0", "22", "65535", "65536", "role-A", "k:v", " ",
                        ]).prop_map(str::to_string),
                        "\\PC{0,3}",
                    ],
                    0..12,
                ),
            ) {
                let spec = parts.concat();
                if let Ok(rule) = parse_rule_spec(&spec) {
                    let protocol = rule["protocol"].as_str().unwrap();
                    prop_assert!(["ANY", "TCP", "UDP", "ICMP"].contains(&protocol));
                    if let Some(range) = rule["portRange"].as_object() {
                        let (from, to) = (range["from"].as_u64().unwrap(), range["to"].as_u64().unwrap());
                        prop_assert!(1 <= from && from <= to && to <= 65535, "{}", rule);
                        prop_assert_ne!(protocol, "ICMP");
                    }
                    let tags: Vec<&Value> = rule["allowedTags"].as_array().into_iter().flatten().collect();
                    let distinct: BTreeSet<String> = tags.iter().map(|t| t.to_string()).collect();
                    prop_assert_eq!(distinct.len(), tags.len(), "repeated tag in {}", rule);
                }
            }
        }
    }
}
