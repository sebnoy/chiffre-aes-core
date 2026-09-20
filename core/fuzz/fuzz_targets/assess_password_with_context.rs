//! Fuzz `assess_password_with_context` (politique de mot de passe).
//!
//! Cette fonction reçoit, dans les applications qui intègrent le crate, ce
//! que l'utilisateur tape au clavier — donc n'importe quelle chaîne Unicode
//! (émojis, caractères combinants, très longues saisies, chaîne vide) — et
//! elle est appelée à chaque frappe pour alimenter un indicateur de
//! robustesse. Elle est documentée comme **infaillible** : la propriété
//! recherchée est donc l'absence de panic, plus la cohérence de la valeur
//! retournée (le score reste dans 0..=4, les drapeaux correspondent aux
//! constantes de la politique, les codes de retour sont stables).
//!
//! Format d'entrée : le mot de passe, puis jusqu'à quatre termes de contexte
//! utilisateur, séparés par l'octet NUL. Les octets invalides en UTF-8 sont
//! remplacés (`from_utf8_lossy`) : on fuzz des chaînes valides.

#![no_main]

use chiffre_aes_core::password_policy::{assess_password_with_context, MIN_LENGTH, REQUIRED_SCORE};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    let mut parts = text.split('\u{0}');
    let password: Zeroizing<String> = Zeroizing::new(parts.next().unwrap_or("").to_string());
    let context: Vec<String> = parts.take(4).map(str::to_string).collect();
    let context_refs: Vec<&str> = context.iter().map(String::as_str).collect();

    let a = assess_password_with_context(&password, &context_refs);

    assert!(a.score <= 4);
    assert!(!a.label.is_empty());
    assert_eq!(a.meets_min_length, password.chars().count() >= MIN_LENGTH);
    assert_eq!(a.meets_score_threshold, a.score >= REQUIRED_SCORE);
    assert_eq!(a.is_acceptable(), a.meets_min_length && a.meets_score_threshold);
    assert_eq!(a.warning.is_some(), a.warning_code.is_some());
    assert_eq!(a.suggestions.len(), a.suggestion_codes.len());
    for code in a.warning_code.iter().chain(a.suggestion_codes.iter()) {
        assert!(!code.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric()));
    }
});
