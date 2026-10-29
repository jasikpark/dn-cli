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

/// Reject an id that passes [`validate_id`] but isn't shaped like one the
/// API issues: `<prefix>-` followed by 26 upper-case letters or digits, the
/// pattern the spec gives for every id it documents. For a flag a script
/// may fill from the wrong field, this fails locally with the expected
/// shape instead of a round trip to a 400. `kind` names the resource in the
/// message; `prefix` is the id's own, which can differ (`endpoint OIDC
/// user` ids start with `eoidcuser-`).
pub fn validate_id_shape(kind: &str, prefix: &str, id: &str) -> anyhow::Result<()> {
    validate_id(kind, id)?;
    let well_formed = id
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|rest| {
            rest.len() == 26
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        });
    if !well_formed {
        bail!(
            "{kind} id must look like {prefix}-XXXXXXXXXXXXXXXXXXXXXXXXXX (26 letters or digits)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_id_shape_wants_the_prefix_and_26_characters() {
        assert!(validate_id_shape("role", "role", "role-ABCDEFGHIJKLMNOPQRSTUVWXYZ").is_ok());
        assert!(validate_id_shape("role", "role", "role-01234567890123456789012345").is_ok());
        assert!(
            validate_id_shape(
                "endpoint OIDC user",
                "eoidcuser",
                "eoidcuser-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
            .is_ok()
        );
        for bad in [
            "notarole",
            "role-",
            "role-ABC",
            "role-ABCDEFGHIJKLMNOPQRSTUVWXY",
            "role-ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
            "role-abcdefghijklmnopqrstuvwxyz",
            "role-ABCDEFGHIJKLMNOPQRSTUVWX_Z",
            "host-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "role-ABCDEFGHIJKLMNOPQRSTUVWXYZ-",
        ] {
            let err = validate_id_shape("role", "role", bad)
                .unwrap_err()
                .to_string();
            assert!(err.contains("must look like role-"), "{bad:?}: {err}");
        }
        // Bad characters are reported as such, before the shape.
        assert_eq!(
            validate_id_shape("role", "role", "role/1")
                .unwrap_err()
                .to_string(),
            "role id contains invalid character '/'"
        );
    }

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
