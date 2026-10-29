//! The mock id generator in `tests/common` produces ids shaped like the
//! API's, deterministically.

mod common;

use common::{any_id, base32, mock_id, mock_ids};
use proptest::prelude::*;

fn is_api_shaped(id: &str, kind: &str) -> bool {
    let Some(rest) = id.strip_prefix(kind).and_then(|r| r.strip_prefix('-')) else {
        return false;
    };
    rest.len() == 26
        && rest
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

#[test]
fn base32_matches_rfc_4648_vectors() {
    // RFC 4648 section 10, padding stripped.
    assert_eq!(base32(b""), "");
    assert_eq!(base32(b"f"), "MY");
    assert_eq!(base32(b"fo"), "MZXQ");
    assert_eq!(base32(b"foo"), "MZXW6");
    assert_eq!(base32(b"foob"), "MZXW6YQ");
    assert_eq!(base32(b"fooba"), "MZXW6YTB");
    assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
}

#[test]
fn a_mock_id_is_shaped_like_a_real_one() {
    let real = "host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI";
    assert!(is_api_shaped(real, "host"));
    for kind in ["host", "role", "network", "tag", "route", "eoidcuser"] {
        let id = mock_id(kind, "build server");
        assert!(is_api_shaped(&id, kind), "{id}");
        assert_eq!(id.len(), real.len() - "host".len() + kind.len());
    }
}

#[test]
fn the_same_label_gives_the_same_id_and_other_labels_differ() {
    assert_eq!(
        mock_id("host", "build server"),
        mock_id("host", "build server")
    );
    assert_ne!(
        mock_id("host", "build server"),
        mock_id("host", "build server 2")
    );
    assert_eq!(
        mock_id("host", "x").strip_prefix("host-"),
        mock_id("role", "x").strip_prefix("role-"),
        "the kind is only the prefix"
    );
    let ids = mock_ids("route", "lab", 5);
    assert_eq!(ids.len(), 5);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 5);
}

#[test]
fn a_mock_id_is_stable_across_runs() {
    // Snapshots may contain these, so the mapping must never drift.
    assert_eq!(
        mock_id("host", "build server"),
        "host-NDTFQFDK72BY35SISGTVL2NLHA"
    );
}

proptest! {
    #[test]
    fn any_id_only_makes_api_shaped_ids(id in any_id("role")) {
        prop_assert!(is_api_shaped(&id, "role"), "{id}");
    }
}
