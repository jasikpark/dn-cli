//! Helpers shared by the integration tests. Each test binary that wants
//! them declares `mod common;`.
//!
//! Real Defined ids are a kind prefix and 16 random bytes in unpadded
//! RFC 4648 base32: `host-KQ4ZB7MXRWEPNA2C5TJ3YVHLDI`, 26 characters of
//! `A-Z2-7`. The spec's patterns (`^role-[A-Z0-9]{26}$`) agree. Mock ids
//! that look like that keep fixtures honest about width and character set
//! without anyone having to type one.

#![allow(dead_code)]

use proptest::prelude::*;

/// Alphabet of RFC 4648 base32, which the API's ids use.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A deterministic mock id for `kind` (`host`, `role`, `network`, `tag`,
/// `route`, `eoidcuser`, …), derived from `label`. The same label always
/// gives the same id, so a test can say `mock_id("host", "build server")`
/// in two places and mean one host; different labels give ids that differ
/// in every position with overwhelming likelihood.
pub fn mock_id(kind: &str, label: &str) -> String {
    let mut state = fnv1a(label.as_bytes());
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&splitmix64(&mut state).to_be_bytes());
    bytes[8..].copy_from_slice(&splitmix64(&mut state).to_be_bytes());
    format!("{kind}-{}", base32(&bytes))
}

/// `n` distinct mock ids for `kind`, labelled `"{label} {i}"`.
pub fn mock_ids(kind: &str, label: &str, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| mock_id(kind, &format!("{label} {i}")))
        .collect()
}

/// A proptest strategy over well-formed ids of `kind`, for fuzzing code
/// that parses or validates them.
pub fn any_id(kind: &'static str) -> impl Strategy<Value = String> {
    prop::array::uniform16(any::<u8>()).prop_map(move |bytes| format!("{kind}-{}", base32(&bytes)))
}

/// Unpadded RFC 4648 base32: 16 bytes become 26 characters, the last one
/// carrying 3 bits.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
