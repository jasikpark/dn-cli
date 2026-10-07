use anyhow::bail;

/// Reject resource ids that are empty or contain anything but ASCII letters,
/// digits, `-` and `_` (ids look like `host-ABC123`), so a typo or a `.`/`..`
/// segment a proxy might normalize can't become a different request path.
/// The API is the authority on whether the id exists. `kind` names the
/// resource in the error ("host id contains invalid character '/'").
pub fn validate_id(kind: &str, id: &str) -> anyhow::Result<()> {
    if id.is_empty() {
        bail!("{kind} id must not be empty");
    }
    if let Some(c) = id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    {
        bail!("{kind} id contains invalid character {c:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_id_accepts_id_characters() {
        for ok in [
            "host-ABC123",
            "host_A-1",
            "role-ABC_123",
            "network-ZJOW3QUQ_X5",
        ] {
            assert!(validate_id("host", ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn validate_id_rejects_path_and_non_ascii_characters() {
        for bad in [
            "",
            ".",
            "..",
            " host-1",
            "role abc",
            "host-1%2F..",
            "host-1?admin=true",
            "host-1#frag",
            "host-1/../../etc",
            "role-\u{202e}x",
            "rôle",
        ] {
            assert!(validate_id("host", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validate_id_names_the_resource_kind() {
        assert_eq!(
            validate_id("network", "").unwrap_err().to_string(),
            "network id must not be empty"
        );
        assert_eq!(
            validate_id("role", "a/b").unwrap_err().to_string(),
            "role id contains invalid character '/'"
        );
    }
}
