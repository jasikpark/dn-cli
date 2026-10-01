use anyhow::{Context, anyhow};
use serde_json::{Value, json};

use crate::api::Client;
use crate::cli::HostCreateArgs;
use crate::error::InvalidArgument;
use crate::output::sanitize_for_display;

pub fn hosts_create(client: &Client, args: &HostCreateArgs, json: bool) -> anyhow::Result<()> {
    // Auto-assigning an IPv4 means sending the network's own IPv4 prefix, so
    // the network is fetched only while IPv4 is still undecided.
    let auto_ipv4 = wants_auto_ipv4(args);
    let (network_id, ipv4_cidr) = match &args.network {
        Some(id) => {
            let cidr = if auto_ipv4 {
                let network = client.get_network(id).with_context(|| {
                    format!(
                        "could not read network {id} to auto-assign an IPv4 (the API key needs \
                         networks:read; pass --ipv4 <ADDR|CIDR> or --no-ipv4 to skip the lookup)"
                    )
                })?;
                network_ipv4_cidr(&network["data"])
            } else {
                None
            };
            (id.clone(), cidr)
        }
        None => {
            let networks = client.list_networks()?;
            let network = pick_network(&networks)?;
            let id = network
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("network list response missing 'id' on the only entry"))?;
            let cidr = if auto_ipv4 {
                network_ipv4_cidr(network)
            } else {
                None
            };
            (id.to_owned(), cidr)
        }
    };

    let body = build_host_create_body(args, &network_id, ipv4_cidr.as_deref());
    let res = client.create_host_with_enrollment(&body)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    print!("{}", render_host_create_human(&res));
    Ok(())
}

/// Reject lighthouse/relay configurations the API would also reject, but with
/// a clearer message than `ERR_INVALID_VALUE` from a round-trip away. The
/// pairing rules (lighthouse needs static address + non-zero port; relay
/// needs non-zero port) come straight from the v2 host-create error examples.
pub fn validate_create_preflight(args: &HostCreateArgs) -> anyhow::Result<()> {
    if args.lighthouse {
        if args.static_addresses.is_empty() {
            return Err(anyhow!(
                "--lighthouse requires at least one --static-address <ip:port>"
            ));
        }
        if args.listen_port.unwrap_or(0) == 0 {
            return Err(anyhow!(
                "--lighthouse requires --listen-port <port> (non-zero)"
            ));
        }
    }
    if args.relay && args.listen_port.unwrap_or(0) == 0 {
        return Err(anyhow!("--relay requires --listen-port <port> (non-zero)"));
    }
    Ok(())
}

/// Pick the account's only network from a `GET /v2/networks` page. Returns a
/// usefully-typed error when auto-pick is ambiguous (0 networks → tell user
/// to create one; ≥2, or more pages → tell user to pass --network), so the
/// caller doesn't have to know the shape of the response to recover.
fn pick_network(networks: &Value) -> anyhow::Result<&Value> {
    let rows = networks
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let has_more = networks
        .get("metadata")
        .and_then(|m| m.get("hasNextPage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match (rows.len(), has_more) {
        (0, _) => Err(anyhow!(
            "no networks found in this account — create one in the web client first"
        )),
        (1, false) => Ok(&rows[0]),
        _ => Err(InvalidArgument(anyhow!(
            "multiple networks found — pass --network <id> to disambiguate (see `dn network list`)"
        ))
        .into()),
    }
}

/// Whether `host create` should have the server pick an IPv4: neither an
/// explicit `--ipv4` nor `--no-ipv4` has settled it.
fn wants_auto_ipv4(args: &HostCreateArgs) -> bool {
    args.ipv4.is_none() && !args.no_ipv4
}

/// The network's IPv4 prefix from its `cidrs` list, or `None` on a v6-only
/// network. Sent as an `ipAddresses` entry it makes the server auto-assign an
/// IPv4 inside that prefix; the API honours only the network's exact prefix
/// (sub-prefixes are rejected), so this is the one CIDR worth sending.
fn network_ipv4_cidr(network: &Value) -> Option<String> {
    network
        .get("cidrs")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|cidr| {
            cidr.split_once('/')
                .is_some_and(|(addr, _)| addr.parse::<std::net::Ipv4Addr>().is_ok())
        })
        .map(str::to_owned)
}

/// Assemble the JSON body for `POST /v2/host-and-enrollment-code` from parsed
/// CLI args. Pure (no I/O) so the body construction is unit-testable without
/// hitting the wire. Optional fields are omitted entirely when unset rather
/// than sent as null — the API treats absent and null the same, but a tighter
/// payload makes API logs easier to diff later.
///
/// `ipv4_auto_cidr` is the network's IPv4 prefix, sent in place of an explicit
/// `--ipv4` so the server picks an address inside it. Without either, the
/// server creates a v6-only host on every network but a legacy v4-only one.
fn build_host_create_body(
    args: &HostCreateArgs,
    network_id: &str,
    ipv4_auto_cidr: Option<&str>,
) -> Value {
    let mut body = json!({
        "name": args.name,
        "networkID": network_id,
    });
    let obj = body.as_object_mut().expect("freshly built object");

    if let Some(role) = &args.role {
        obj.insert("roleID".into(), json!(role));
    }
    let mut ips: Vec<&str> = Vec::new();
    if !args.no_ipv4
        && let Some(v4) = args.ipv4.as_deref().or(ipv4_auto_cidr)
    {
        ips.push(v4);
    }
    if let Some(v6) = &args.ipv6 {
        ips.push(v6);
    }
    if !ips.is_empty() {
        obj.insert("ipAddresses".into(), json!(ips));
    }
    if !args.static_addresses.is_empty() {
        obj.insert("staticAddresses".into(), json!(args.static_addresses));
    }
    if let Some(p) = args.listen_port {
        obj.insert("listenPort".into(), json!(p));
    }
    if args.lighthouse {
        obj.insert("isLighthouse".into(), json!(true));
    }
    if args.relay {
        obj.insert("isRelay".into(), json!(true));
    }
    if !args.tags.is_empty() {
        obj.insert("tags".into(), json!(args.tags));
    }
    if let Some(c) = args.code_lifetime {
        obj.insert("codeLifetimeSeconds".into(), json!(c));
    }
    body
}

/// Human-readable post-create summary. Surfaces what the user needs to act on
/// next: the OTP to feed `dnclient enroll`, and the deny-all-default warning
/// so a fresh user doesn't wonder why the hosts can't reach each other yet.
///
/// Treated as the user-facing UX surface — strings, ordering, and emphasis
/// are deliberately open to revision; the structure (extract → format → emit)
/// is what's load-bearing.
fn render_host_create_human(res: &Value) -> String {
    let data = res.get("data");
    let host = data.and_then(|d| d.get("host"));
    let enrollment = data.and_then(|d| d.get("enrollmentCode"));

    let str_field = |v: Option<&Value>, key: &str| -> String {
        v.and_then(|h| h.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let name = str_field(host, "name");
    let id = str_field(host, "id");
    let ips = host
        .and_then(|h| h.get("ipAddresses"))
        .and_then(Value::as_array)
        .map(|addrs| {
            addrs
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let is_lighthouse = host
        .and_then(|h| h.get("isLighthouse"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_relay = host
        .and_then(|h| h.get("isRelay"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let kind = if is_lighthouse {
        "lighthouse"
    } else if is_relay {
        "relay"
    } else {
        "host"
    };
    let code = str_field(enrollment, "code");

    let name = sanitize_for_display(&name);
    let ips = sanitize_for_display(&ips);

    let mut out = String::new();
    out.push_str(&format!("Created {kind} \"{name}\" ({id})\n"));
    if !ips.is_empty() {
        out.push_str(&format!("  IP addresses: {ips}\n"));
    }
    if !code.is_empty() {
        out.push('\n');
        out.push_str("To enroll the device, install dnclient and run:\n");
        out.push_str(&format!("  dnclient enroll {code}\n"));
    }
    out.push('\n');
    out.push_str("Note: the default role denies all inbound traffic. New hosts will be on\n");
    out.push_str("the network but unable to reach each other until a role with firewall\n");
    out.push_str("rules is created and assigned (see `dn role list`), unless one of their\n");
    out.push_str("tags carries firewall rules (see `dn tag get`).\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(
        name: &str,
        network: Option<&str>,
        lighthouse: bool,
        relay: bool,
        static_addresses: Vec<&str>,
        listen_port: Option<u16>,
    ) -> HostCreateArgs {
        HostCreateArgs {
            name: name.into(),
            network: network.map(str::to_owned),
            role: None,
            lighthouse,
            relay,
            ipv4: None,
            no_ipv4: false,
            ipv6: None,
            static_addresses: static_addresses.into_iter().map(str::to_owned).collect(),
            listen_port,
            tags: Vec::new(),
            code_lifetime: None,
        }
    }

    #[test]
    fn pick_network_returns_sole_network_when_one() {
        let networks = json!({
            "data": [{"id": "network-only", "cidrs": ["100.100.0.0/22"]}],
            "metadata": {"hasNextPage": false},
        });
        let network = pick_network(&networks).unwrap();
        assert_eq!(network["id"], json!("network-only"));
        assert_eq!(network["cidrs"], json!(["100.100.0.0/22"]));
    }

    #[test]
    fn pick_network_errors_on_zero_networks() {
        let networks = json!({"data": [], "metadata": {"hasNextPage": false}});
        let err = pick_network(&networks).unwrap_err().to_string();
        assert!(err.contains("no networks"));
    }

    #[test]
    fn pick_network_errors_on_multiple_in_data() {
        let networks = json!({
            "data": [{"id": "a"}, {"id": "b"}],
            "metadata": {"hasNextPage": false},
        });
        let err = pick_network(&networks).unwrap_err().to_string();
        assert!(err.contains("--network"));
    }

    #[test]
    fn pick_network_errors_when_more_pages_exist() {
        // Single row but a second page → can't safely auto-pick.
        let networks = json!({
            "data": [{"id": "a"}],
            "metadata": {"hasNextPage": true},
        });
        assert!(pick_network(&networks).is_err());
    }

    #[test]
    fn wants_auto_ipv4_only_when_neither_flag_settles_it() {
        let mut a = args("h", None, false, false, vec![], None);
        assert!(wants_auto_ipv4(&a));
        a.no_ipv4 = true;
        assert!(!wants_auto_ipv4(&a));
        a.no_ipv4 = false;
        a.ipv4 = Some("100.100.0.0/22".into());
        assert!(!wants_auto_ipv4(&a));
    }

    #[test]
    fn network_ipv4_cidr_picks_v4_among_mixed_cidrs() {
        let network = json!({"cidrs": ["fdef:c0:c0::/48", "100.100.0.0/22"]});
        assert_eq!(
            network_ipv4_cidr(&network).as_deref(),
            Some("100.100.0.0/22")
        );
    }

    #[test]
    fn network_ipv4_cidr_is_none_without_a_v4_prefix() {
        assert_eq!(
            network_ipv4_cidr(&json!({"cidrs": ["fdef:c0:c0::/48"]})),
            None
        );
        assert_eq!(network_ipv4_cidr(&json!({})), None);
    }

    #[test]
    fn build_body_minimal_omits_all_optionals() {
        let a = args("server", None, false, false, vec![], None);
        let body = build_host_create_body(&a, "network-1", None);
        assert_eq!(
            body,
            json!({"name": "server", "networkID": "network-1"}),
            "optional fields must be absent (not null) when unset"
        );
    }

    #[test]
    fn build_body_lighthouse_payload() {
        let mut a = args("lh", None, true, false, vec!["1.2.3.4:4242"], Some(4242));
        a.ipv4 = Some("100.100.0.5".into());
        let body = build_host_create_body(&a, "network-1", None);
        assert_eq!(body["isLighthouse"], json!(true));
        assert_eq!(body["staticAddresses"], json!(["1.2.3.4:4242"]));
        assert_eq!(body["listenPort"], json!(4242));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5"]));
        assert!(body.get("isRelay").is_none());
    }

    #[test]
    fn build_body_dual_stack_ips_preserve_v4_then_v6_order() {
        let mut a = args("h", None, false, false, vec![], None);
        a.ipv4 = Some("100.100.0.5".into());
        a.ipv6 = Some("fdef::42".into());
        let body = build_host_create_body(&a, "n", None);
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5", "fdef::42"]));
    }

    #[test]
    fn build_body_sends_network_cidr_to_auto_assign_ipv4() {
        let a = args("h", None, false, false, vec![], None);
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.0/22"]));
    }

    #[test]
    fn build_body_explicit_ipv4_wins_over_network_cidr() {
        let mut a = args("h", None, false, false, vec![], None);
        a.ipv4 = Some("100.100.0.5".into());
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["100.100.0.5"]));
    }

    #[test]
    fn build_body_no_ipv4_yields_v6_only_host() {
        let mut a = args("h", None, false, false, vec![], None);
        a.no_ipv4 = true;
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert!(body.get("ipAddresses").is_none());
        a.ipv6 = Some("fdef::42".into());
        let body = build_host_create_body(&a, "n", Some("100.100.0.0/22"));
        assert_eq!(body["ipAddresses"], json!(["fdef::42"]));
    }

    #[test]
    fn build_body_includes_tags_and_code_lifetime() {
        let mut a = args("h", None, false, false, vec![], None);
        a.tags = vec!["env:prod".into(), "team:gaming".into()];
        a.code_lifetime = Some(3600);
        let body = build_host_create_body(&a, "n", None);
        assert_eq!(body["tags"], json!(["env:prod", "team:gaming"]));
        assert_eq!(body["codeLifetimeSeconds"], json!(3600));
    }

    #[test]
    fn preflight_lighthouse_needs_static_address() {
        let a = args("lh", None, true, false, vec![], Some(4242));
        let err = validate_create_preflight(&a).unwrap_err().to_string();
        assert!(err.contains("--static-address"));
    }

    #[test]
    fn preflight_lighthouse_needs_nonzero_listen_port() {
        let a = args("lh", None, true, false, vec!["1.2.3.4:4242"], None);
        assert!(validate_create_preflight(&a).is_err());
        let a = args("lh", None, true, false, vec!["1.2.3.4:4242"], Some(0));
        assert!(validate_create_preflight(&a).is_err());
    }

    #[test]
    fn preflight_relay_needs_listen_port() {
        let a = args("r", None, false, true, vec![], None);
        let err = validate_create_preflight(&a).unwrap_err().to_string();
        assert!(err.contains("--listen-port"));
    }

    #[test]
    fn preflight_ok_for_regular_host_with_no_flags() {
        let a = args("plain", None, false, false, vec![], None);
        assert!(validate_create_preflight(&a).is_ok());
    }

    #[test]
    fn render_human_includes_otp_and_deny_warning() {
        let res = json!({
            "data": {
                "host": {
                    "id": "host-1",
                    "name": "mc-server",
                    "ipAddresses": ["100.100.0.5"],
                    "isLighthouse": false,
                    "isRelay": false,
                },
                "enrollmentCode": {"code": "ABC123XYZ", "lifetimeSeconds": 86400},
            }
        });
        let out = render_host_create_human(&res);
        assert!(out.contains("host"));
        assert!(out.contains("mc-server"));
        assert!(out.contains("ABC123XYZ"));
        assert!(out.contains("dnclient enroll"));
        assert!(out.to_lowercase().contains("default role"));
    }

    #[test]
    fn render_human_labels_lighthouse_when_set() {
        let res = json!({
            "data": {
                "host": {"id": "host-lh", "name": "lh-1", "isLighthouse": true},
                "enrollmentCode": {"code": "OTP"},
            }
        });
        assert!(render_host_create_human(&res).contains("lighthouse"));
    }
}
