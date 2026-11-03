use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use serde_json::Value;

use crate::api::{ApiError, Client};
use crate::cli::HostWaitArgs;
use crate::error::TimedOut;
use crate::ids::validate_id;
use crate::output::{
    OutputMode, data_object, joined_field, render_details, sanitize_for_display, str_field,
};

/// Reject a malformed host id or `--since` before credentials are resolved.
pub fn validate_wait_preflight(args: &HostWaitArgs) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    if let Some(since) = &args.since {
        parse_since(since, Timestamp::now())?;
    }
    Ok(())
}

/// Poll a host until it checks in, then show it. `--json` prints the host as
/// `host get` would; a wait that runs out of time fails with `ERR_TIMEOUT`.
pub fn hosts_wait(client: &Client, args: &HostWaitArgs, output: OutputMode) -> anyhow::Result<()> {
    validate_id("host", &args.host_id)?;
    let since = args
        .since
        .as_deref()
        .map(|s| parse_since(s, Timestamp::now()))
        .transpose()?;
    let plan = Plan {
        host_id: &args.host_id,
        since,
        timeout: args.timeout,
        interval: args.interval,
    };
    let res = wait_for_check_in(
        &plan,
        || client.get_host(&args.host_id),
        &mut SystemClock(Instant::now()),
        |progress| match progress {
            // The JSON face stays quiet on stderr until something goes wrong.
            Progress::Waiting(host) if output == OutputMode::Human => eprintln!(
                "Waiting for {} to check in (up to {}, every {})...",
                host_label(&args.host_id, host),
                friendly(args.timeout),
                friendly(args.interval),
            ),
            Progress::Waiting(_) => {}
            Progress::Retrying(err) => eprintln!(
                "note: still waiting; this check failed: {}",
                sanitize_for_display(&format!("{err:#}"))
            ),
        },
    )?;
    output.emit(&res, |res| {
        print!(
            "{}",
            render_checked_in(&args.host_id, data_object(res, "host")?)
        );
        Ok(())
    })
}

/// What one wait is for: the host, the earliest check-in that counts, how
/// long to keep asking, and how often.
struct Plan<'a> {
    host_id: &'a str,
    since: Option<Timestamp>,
    timeout: Duration,
    interval: Duration,
}

/// What the wait tells the caller while it runs.
enum Progress<'a> {
    /// The first answer said the host hasn't checked in yet; sent once.
    Waiting(&'a Value),
    /// A check failed in a way that may pass (a dropped connection, a 5xx),
    /// and the wait carries on.
    Retrying(&'a anyhow::Error),
}

/// Time as the wait sees it, so tests can run a ten-minute wait instantly.
trait Clock {
    /// Time since the wait started.
    fn elapsed(&self) -> Duration;
    fn sleep(&mut self, d: Duration);
}

struct SystemClock(Instant);

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Ask `poll` for the host every `plan.interval` until it has checked in,
/// returning that response. The first check must succeed: an error there is
/// a wrong id, key, or URL, and waiting won't fix it. Later, a dropped
/// connection or a 5xx is reported and retried, while any other API error
/// (the host was deleted, the key revoked) ends the wait. The last check
/// lands on the deadline, so a host that checks in just before it counts.
fn wait_for_check_in(
    plan: &Plan,
    mut poll: impl FnMut() -> anyhow::Result<Value>,
    clock: &mut impl Clock,
    mut progress: impl FnMut(Progress),
) -> anyhow::Result<Value> {
    let mut last: Option<Value> = None;
    loop {
        match poll() {
            Ok(res) => {
                let host = checked_host(plan.host_id, &res)?;
                if checked_in(host, plan.since)? {
                    return Ok(res);
                }
                if last.is_none() {
                    progress(Progress::Waiting(host));
                }
                last = Some(res);
            }
            Err(err) if last.is_some() && is_transient(&err) => {
                progress(Progress::Retrying(&err));
            }
            Err(err) => return Err(err),
        }
        let elapsed = clock.elapsed();
        if elapsed >= plan.timeout {
            let host = last.as_ref().and_then(|res| res.get("data"));
            return Err(TimedOut(timeout_message(plan, host)).into());
        }
        clock.sleep(plan.interval.min(plan.timeout - elapsed));
    }
}

/// The host in a `host get` response, refusing one for a different host.
fn checked_host<'a>(requested: &str, res: &'a Value) -> anyhow::Result<&'a Value> {
    let host = data_object(res, "host")?;
    if let Some(got) = host.get("id").and_then(Value::as_str)
        && got != requested
    {
        bail!(
            "unexpected response: asked for {requested} but the API returned host {}",
            sanitize_for_display(got)
        );
    }
    Ok(host)
}

/// A failure worth retrying mid-wait: one that never got an API response,
/// or a server-side 5xx. A 4xx means the next check would fail the same way.
fn is_transient(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ApiError>()
        .is_none_or(|api| api.status >= 500)
}

/// `metadata.lastSeenAt`, which the API leaves `null` until the host first
/// checks in. Anything other than a string or `null` is a broken response.
fn last_seen(host: &Value) -> anyhow::Result<Option<&str>> {
    match host.get("metadata").and_then(|m| m.get("lastSeenAt")) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(other) => bail!(
            "unexpected response: metadata.lastSeenAt is {}, not a timestamp",
            sanitize_for_display(&other.to_string())
        ),
    }
}

/// Whether the host has checked in: ever, or at or after `since`.
fn checked_in(host: &Value, since: Option<Timestamp>) -> anyhow::Result<bool> {
    let Some(seen) = last_seen(host)? else {
        return Ok(false);
    };
    let Some(since) = since else {
        return Ok(true);
    };
    let seen = Timestamp::from_str(seen).map_err(|_| {
        anyhow!(
            "unexpected response: metadata.lastSeenAt \"{}\" isn't an RFC 3339 timestamp",
            sanitize_for_display(seen)
        )
    })?;
    Ok(seen >= since)
}

/// `--since` as a timestamp. `now` is cut to the whole second, because the
/// API reports `lastSeenAt` in whole seconds: a check-in a moment after the
/// wait started must not read as one from before it.
fn parse_since(s: &str, now: Timestamp) -> anyhow::Result<Timestamp> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("now") {
        return Ok(Timestamp::from_second(now.as_second())?);
    }
    Timestamp::from_str(s).map_err(|e| {
        anyhow!("--since: expected an RFC 3339 timestamp like 2026-11-03T18:00:00Z, or `now` ({e})")
    })
}

/// Why the wait gave up, and what to check next.
fn timeout_message(plan: &Plan, host: Option<&Value>) -> String {
    let id = plan.host_id;
    let label = host.map_or_else(|| id.to_string(), |h| host_label(id, h));
    let what = match plan.since {
        Some(since) => format!(
            "{label} hasn't checked in since {}",
            since.strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
        None => format!("{label} hasn't checked in"),
    };
    let seen = host
        .and_then(|h| last_seen(h).ok().flatten())
        .map(|s| format!(" (last seen {})", sanitize_for_display(s)))
        .unwrap_or_default();
    format!(
        "{what} after {}{seen}. Check that `dnclient enroll` finished on the device \
         and that it can reach the internet, then run `dn host wait {id}` again",
        friendly(plan.timeout)
    )
}

/// `"name" (id)`, or the bare id for a host without a usable name.
fn host_label(requested: &str, host: &Value) -> String {
    match sanitize_for_display(str_field(host, "name")).trim() {
        "" => requested.to_string(),
        shown => format!("\"{shown}\" ({requested})"),
    }
}

/// A duration as `1m 30s`.
fn friendly(d: Duration) -> String {
    SignedDuration::try_from(d).map_or_else(|_| format!("{d:?}"), |d| format!("{d:#}"))
}

/// The human view once a host has checked in: who, when, and what it runs.
fn render_checked_in(requested: &str, host: &Value) -> String {
    let meta = &host["metadata"];
    let client = [str_field(meta, "platform"), str_field(meta, "version")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let client = match (client.as_str(), str_field(meta, "os")) {
        (c, "") => c.to_string(),
        ("", os) => os.to_string(),
        (c, os) => format!("{c} on {os}"),
    };
    let mut out = format!("{} checked in.\n", host_label(requested, host));
    out.push_str(&render_details(&[
        ("Last seen", str_field(meta, "lastSeenAt").to_string()),
        ("Client", client),
        ("IP addresses", joined_field(host, "ipAddresses")),
    ]));
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::json;

    use super::*;

    const ID: &str = "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI";

    /// A clock that only moves when the wait sleeps, recording each sleep.
    #[derive(Default)]
    struct FakeClock {
        now: Duration,
        sleeps: Vec<Duration>,
    }

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            self.now
        }

        fn sleep(&mut self, d: Duration) {
            self.now += d;
            self.sleeps.push(d);
        }
    }

    fn host(last_seen: Value) -> anyhow::Result<Value> {
        Ok(json!({"data": {
            "id": ID,
            "name": "Build Server",
            "metadata": {"lastSeenAt": last_seen, "platform": "dnclient", "version": "0.9.3", "os": "linux"},
        }, "metadata": {}}))
    }

    fn never_seen() -> anyhow::Result<Value> {
        host(Value::Null)
    }

    fn seen(at: &str) -> anyhow::Result<Value> {
        host(json!(at))
    }

    fn api_error(status: u16) -> anyhow::Result<Value> {
        Err(ApiError {
            status,
            request_id: None,
            errors: vec![],
        }
        .into())
    }

    fn plan(since: Option<&str>, timeout: u64, interval: u64) -> Plan<'static> {
        Plan {
            host_id: ID,
            since: since.map(|s| s.parse().unwrap()),
            timeout: Duration::from_secs(timeout),
            interval: Duration::from_secs(interval),
        }
    }

    /// Run a wait against `answers` in order, a final `Ok` repeating, and
    /// return its result, the clock, how many checks ran, and what it said.
    fn run(
        plan: &Plan,
        answers: Vec<anyhow::Result<Value>>,
    ) -> (anyhow::Result<Value>, FakeClock, usize, Vec<String>) {
        let answers = RefCell::new(VecDeque::from(answers));
        let mut polls = 0;
        let mut clock = FakeClock::default();
        let mut said = Vec::new();
        let result = wait_for_check_in(
            plan,
            || {
                polls += 1;
                let mut answers = answers.borrow_mut();
                match answers.front() {
                    Some(Ok(v)) if answers.len() == 1 => Ok(v.clone()),
                    _ => answers.pop_front().expect("polled past the last answer"),
                }
            },
            &mut clock,
            |p| {
                said.push(match p {
                    Progress::Waiting(h) => format!("waiting {}", str_field(h, "id")),
                    Progress::Retrying(e) => format!("retrying {e:#}"),
                });
            },
        );
        (result, clock, polls, said)
    }

    #[test]
    fn a_host_that_has_checked_in_returns_at_once() {
        let (res, clock, polls, said) =
            run(&plan(None, 600, 5), vec![seen("2026-11-03T01:00:00Z")]);
        assert_eq!(res.unwrap()["data"]["id"], ID);
        assert_eq!((polls, clock.sleeps.len()), (1, 0));
        assert!(said.is_empty(), "{said:?}");
    }

    #[test]
    fn it_polls_every_interval_until_the_host_checks_in() {
        let (res, clock, polls, said) = run(
            &plan(None, 600, 5),
            vec![never_seen(), never_seen(), seen("2026-11-03T01:00:00Z")],
        );
        assert!(res.is_ok());
        assert_eq!(polls, 3);
        assert_eq!(clock.sleeps, [Duration::from_secs(5); 2]);
        assert_eq!(said, [format!("waiting {ID}")], "said waiting only once");
    }

    #[test]
    fn it_times_out_with_a_final_check_on_the_deadline() {
        let (res, clock, polls, _) = run(&plan(None, 12, 5), vec![never_seen()]);
        let err = res.unwrap_err();
        assert!(err.downcast_ref::<TimedOut>().is_some(), "{err:#}");
        // Checks at 0s, 5s, 10s, and 12s: the last sleep is cut short.
        assert_eq!(polls, 4);
        assert_eq!(
            clock.sleeps,
            [5, 5, 2].map(Duration::from_secs),
            "never sleeps past the deadline"
        );
        let msg = err.to_string();
        assert!(msg.contains(&format!("\"Build Server\" ({ID})")), "{msg}");
        assert!(msg.contains("after 12s"), "{msg}");
        assert!(msg.contains(&format!("dn host wait {ID}")), "{msg}");
    }

    #[test]
    fn a_check_in_found_on_the_deadline_counts() {
        let (res, _, polls, _) = run(
            &plan(None, 5, 5),
            vec![never_seen(), seen("2026-11-03T01:00:00Z")],
        );
        assert!(res.is_ok());
        assert_eq!(polls, 2);
    }

    #[test]
    fn since_ignores_an_older_check_in() {
        let (res, _, polls, _) = run(
            &plan(Some("2026-11-03T01:00:00Z"), 600, 5),
            vec![seen("2026-11-02T12:00:00Z"), seen("2026-11-03T01:00:00Z")],
        );
        assert!(res.is_ok(), "a check-in at the --since second counts");
        assert_eq!(polls, 2);
    }

    #[test]
    fn a_since_timeout_names_the_time_and_the_last_check_in() {
        let (res, _, _, _) = run(
            &plan(Some("2026-11-03T01:00:00Z"), 5, 5),
            vec![seen("2026-11-02T12:00:00Z")],
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("hasn't checked in since 2026-11-03T01:00:00Z"),
            "{msg}"
        );
        assert!(msg.contains("(last seen 2026-11-02T12:00:00Z)"), "{msg}");
    }

    #[test]
    fn a_failed_first_check_ends_the_wait() {
        for first in [
            api_error(404),
            api_error(503),
            Err(anyhow!("connection refused")),
        ] {
            let (res, clock, polls, _) = run(&plan(None, 600, 5), vec![first]);
            assert!(res.is_err());
            assert!(res.unwrap_err().downcast_ref::<TimedOut>().is_none());
            assert_eq!((polls, clock.sleeps.len()), (1, 0));
        }
    }

    #[test]
    fn transient_failures_mid_wait_are_retried() {
        let (res, _, polls, said) = run(
            &plan(None, 600, 5),
            vec![
                never_seen(),
                Err(anyhow!("connection reset")),
                api_error(502),
                seen("2026-11-03T01:00:00Z"),
            ],
        );
        assert!(res.is_ok());
        assert_eq!(polls, 4);
        assert_eq!(said.len(), 3, "{said:?}");
        assert!(said[1].starts_with("retrying connection reset"), "{said:?}");
    }

    #[test]
    fn a_client_error_mid_wait_ends_it() {
        for status in [401, 403, 404] {
            let (res, _, polls, _) =
                run(&plan(None, 600, 5), vec![never_seen(), api_error(status)]);
            let err = res.unwrap_err();
            assert_eq!(err.downcast_ref::<ApiError>().unwrap().status, status);
            assert_eq!(polls, 2);
        }
    }

    #[test]
    fn a_response_for_another_host_is_an_error() {
        let other = json!({"data": {"id": "host-M6TLA3VZQ2NXKC7EWJR5PBYHFO"}});
        let (res, _, _, _) = run(&plan(None, 600, 5), vec![Ok(other)]);
        assert!(res.unwrap_err().to_string().contains("asked for"));
    }

    #[test]
    fn last_seen_reads_null_missing_and_blank_as_never() {
        for host in [
            json!({}),
            json!({"metadata": {}}),
            json!({"metadata": {"lastSeenAt": null}}),
            json!({"metadata": {"lastSeenAt": " "}}),
        ] {
            assert_eq!(last_seen(&host).unwrap(), None, "{host}");
        }
        assert!(last_seen(&json!({"metadata": {"lastSeenAt": 7}})).is_err());
    }

    #[test]
    fn since_needs_a_parseable_last_seen() {
        let host = json!({"metadata": {"lastSeenAt": "yesterday"}});
        assert!(
            checked_in(&host, None).unwrap(),
            "no --since: any value counts"
        );
        let since = "2026-11-03T01:00:00Z".parse().ok();
        assert!(checked_in(&host, since).is_err());
    }

    #[test]
    fn since_takes_a_timestamp_or_now_cut_to_the_second() {
        let now: Timestamp = "2026-11-03T01:02:03.75Z".parse().unwrap();
        assert_eq!(
            parse_since("now", now).unwrap(),
            "2026-11-03T01:02:03Z".parse::<Timestamp>().unwrap()
        );
        assert_eq!(
            parse_since(" NOW ", now).unwrap(),
            parse_since("now", now).unwrap()
        );
        assert_eq!(
            parse_since("2026-11-02T19:00:00-06:00", now).unwrap(),
            "2026-11-03T01:00:00Z".parse::<Timestamp>().unwrap()
        );
        let err = parse_since("yesterday", now).unwrap_err().to_string();
        assert!(err.starts_with("--since: expected"), "{err}");
    }

    #[test]
    fn transient_means_no_response_or_a_server_error() {
        assert!(is_transient(&anyhow!("connection reset")));
        assert!(is_transient(&api_error(500).unwrap_err()));
        assert!(!is_transient(&api_error(499).unwrap_err()));
        assert!(!is_transient(&api_error(404).unwrap_err()));
    }

    #[test]
    fn checked_in_view_names_the_host_and_its_client() {
        let res = seen("2026-11-03T01:00:00Z").unwrap();
        let mut host = res["data"].clone();
        host["ipAddresses"] = json!(["100.100.0.12", "fd00::12"]);
        assert_eq!(
            render_checked_in(ID, &host),
            format!(
                "\"Build Server\" ({ID}) checked in.\n\
                 Last seen:     2026-11-03T01:00:00Z\n\
                 Client:        dnclient 0.9.3 on linux\n\
                 IP addresses:  100.100.0.12, fd00::12\n"
            )
        );
    }

    #[test]
    fn checked_in_view_copes_with_a_sparse_host() {
        let host = json!({"name": "\u{1b}", "metadata": {"lastSeenAt": "2026-11-03T01:00:00Z", "os": "ios"}});
        let out = render_checked_in(ID, &host);
        assert!(out.starts_with(&format!("{ID} checked in.\n")), "{out:?}");
        assert!(out.contains("Client:     ios\n"), "{out:?}");
        assert!(!out.contains("IP addresses"), "{out:?}");
    }

    #[test]
    fn durations_read_like_the_flags() {
        assert_eq!(friendly(Duration::from_secs(90)), "1m 30s");
        assert_eq!(friendly(Duration::from_secs(600)), "10m");
    }
}
