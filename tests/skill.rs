//! The skill tells agents which `dn` release it documents. Knope bumps that
//! number with the crate version; this pins the two together so a hand edit
//! to either can't leave them apart.

const SKILL: &str = include_str!("../skills/defined-networking/SKILL.md");

#[test]
fn the_skill_names_the_dn_version_it_documents() {
    let want = format!("This skill documents `dn` {}.", env!("CARGO_PKG_VERSION"));
    assert!(SKILL.contains(&want), "SKILL.md lacks {want:?}");
}

#[test]
fn every_version_in_the_skill_is_the_crate_version() {
    // Knope's regex rewrites every `x.y.z` in the file, so no other version
    // number may appear in it, or a release would overwrite it.
    let crate_version = env!("CARGO_PKG_VERSION");
    let mut versions = Vec::new();
    for word in SKILL.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let word = word.trim_matches('.');
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            versions.push(word);
        }
    }
    assert!(!versions.is_empty());
    assert!(
        versions.iter().all(|v| *v == crate_version),
        "SKILL.md mentions versions other than {crate_version}: {versions:?}"
    );
}
