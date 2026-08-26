//! Politique de mot de passe, bloquante.
//!
//! Trois règles cumulatives doivent être satisfaites pour qu'un mot de
//! passe soit accepté à la création d'une archive :
//! 1. **Longueur minimale** (12 caractères).
//! 2. **Score `zxcvbn` minimal** (≥ 3 sur 4) — l'estimation d'entropie
//!    fait foi plutôt qu'une règle rigide de classes de caractères
//!    (majuscule/chiffre/spécial...), jugée moins fiable.
//! 3. **Confirmation strictement identique**.
//!
//! Ce module est volontairement autonome et ne dépend d'aucune UI : il est
//! testable en ligne de commande (`chiffre_aes_cli check-password`) ou par tests
//! unitaires, indépendamment de l'interface graphique.

use crate::crypto::Password;
use zxcvbn::zxcvbn;

/// Longueur minimale imposée, en caractères.
pub const MIN_LENGTH: usize = 12;
/// Score `zxcvbn` minimal requis (0 à 4) pour débloquer la validation.
pub const REQUIRED_SCORE: u8 = 3;

/// Résultat d'évaluation d'un mot de passe, destiné à alimenter en temps
/// réel la barre de force et les critères affichés à l'utilisateur.
#[derive(Debug, Clone)]
pub struct PasswordAssessment {
    /// Score d'entropie `zxcvbn`, de 0 (trivial) à 4 (très robuste).
    pub score: u8,
    /// Libellé humain correspondant au score (« très faible » à « très fort »).
    pub label: &'static str,
    /// Le mot de passe atteint-il la longueur minimale ?
    pub meets_min_length: bool,
    /// Le score atteint-il le seuil requis (`REQUIRED_SCORE`) ?
    pub meets_score_threshold: bool,
    /// Avertissement `zxcvbn` le plus pertinent (ex. « mot de passe trop
    /// commun »), à afficher tel quel si présent.
    pub warning: Option<String>,
    /// Suggestions concrètes d'amélioration fournies par `zxcvbn`.
    pub suggestions: Vec<String>,
}

impl PasswordAssessment {
    /// Le mot de passe respecte-t-il toutes les règles de robustesse
    /// (hors confirmation) ? Utilisé pour activer/désactiver le bouton de
    /// validation en temps réel.
    pub fn is_acceptable(&self) -> bool {
        self.meets_min_length && self.meets_score_threshold
    }
}

/// Erreurs de validation bloquante, distinctes pour permettre à l'appelant
/// (CLI/GUI) d'afficher un message ciblé.
#[derive(Debug, thiserror::Error)]
pub enum PasswordPolicyError {
    #[error("mot de passe trop court : {actual} caractère(s), minimum requis {min_length}")]
    TooShort { actual: usize, min_length: usize },

    #[error("mot de passe trop faible (score {score}/4, minimum requis {required}/4){warning_suffix}")]
    TooWeak {
        score: u8,
        required: u8,
        warning_suffix: String,
    },

    #[error("les deux saisies du mot de passe ne correspondent pas")]
    ConfirmationMismatch,
}

/// Évalue un mot de passe (appelé à chaque frappe côté UI). Ne bloque rien
/// en soi — c'est un pur calcul d'information à afficher.
pub fn assess_password(password: &Password) -> PasswordAssessment {
    let len = password.chars().count();
    let meets_min_length = len >= MIN_LENGTH;

    // Depuis zxcvbn 3.0, `zxcvbn(...)` ne peut plus échouer (un mot de
    // passe vide renvoie directement un score `Score::Zero` en interne,
    // cf. changelog "[Breaking] Avoid the possibility for zxcvbn to
    // error") : plus besoin de gérer un `Result` ici. Le score est
    // désormais un enum exhaustif `Score` (et non plus un `u8` brut) :
    // on le convertit via `u8::from` pour conserver le type `u8` déjà
    // utilisé par le reste de l'API de ce module (CLI/GUI).
    let estimate = zxcvbn(password, &[]);
    let score = u8::from(estimate.score());
    // `feedback()` retourne désormais `Option<&Feedback>` (référence, et
    // non plus une valeur possédée) : `Feedback` reste `Clone`, donc un
    // simple `.cloned()` suffit à revenir à une valeur possédée, sans
    // changer la suite de la logique.
    let feedback = estimate.feedback().cloned();
    let meets_score_threshold = score >= REQUIRED_SCORE;

    let (warning, suggestions) = match feedback {
        Some(feedback) => {
            let warning = feedback.warning().map(|w| w.to_string());
            let suggestions = feedback
                .suggestions()
                .iter()
                .map(|s| s.to_string())
                .collect();
            (warning, suggestions)
        }
        None => (None, Vec::new()),
    };

    PasswordAssessment {
        score,
        label: score_label(score),
        meets_min_length,
        meets_score_threshold,
        warning,
        suggestions,
    }
}

/// Libellé humain associé à un score `zxcvbn` (« faible / moyen / fort /
/// très fort » — étendu ici avec « très faible » pour le score 0, afin de
/// couvrir les 5 valeurs possibles de 0 à 4).
fn score_label(score: u8) -> &'static str {
    match score {
        0 => "très faible",
        1 => "faible",
        2 => "moyen",
        3 => "fort",
        _ => "très fort",
    }
}

/// Compare strictement les deux saisies du mot de passe. Comparaison
/// simple : il ne s'agit pas d'une vérification contre un secret stocké
/// (pas de risque d'attaque temporelle exploitable), seulement de la
/// cohérence de deux champs de saisie de l'utilisateur.
pub fn passwords_match(password: &Password, confirmation: &Password) -> bool {
    password.as_str() == confirmation.as_str()
}

/// Validation bloquante complète, à appeler avant toute création d'archive
/// chiffrée : longueur, score, puis confirmation. Retourne
/// l'évaluation complète en cas de succès (utile pour l'affichage final),
/// ou la première règle violée sous forme d'erreur explicite.
pub fn validate_new_password(
    password: &Password,
    confirmation: &Password,
) -> Result<PasswordAssessment, PasswordPolicyError> {
    let assessment = assess_password(password);

    if !assessment.meets_min_length {
        return Err(PasswordPolicyError::TooShort {
            actual: password.chars().count(),
            min_length: MIN_LENGTH,
        });
    }

    if !assessment.meets_score_threshold {
        let warning_suffix = assessment
            .warning
            .as_ref()
            .map(|w| format!(" — {w}"))
            .unwrap_or_default();
        return Err(PasswordPolicyError::TooWeak {
            score: assessment.score,
            required: REQUIRED_SCORE,
            warning_suffix,
        });
    }

    if !passwords_match(password, confirmation) {
        return Err(PasswordPolicyError::ConfirmationMismatch);
    }

    Ok(assessment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn pwd(s: &str) -> Password {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn empty_password_is_rejected_for_length() {
        let p = pwd("");
        let result = validate_new_password(&p, &p);
        assert!(matches!(result, Err(PasswordPolicyError::TooShort { .. })));
    }

    #[test]
    fn short_but_complex_password_is_rejected_for_length() {
        // 8 caractères, forte diversité de classes, mais sous le minimum
        // de longueur : doit échouer sur la longueur, pas sur le score.
        let p = pwd("Ax7!zQ9#");
        assert!(p.chars().count() < MIN_LENGTH);
        let result = validate_new_password(&p, &p);
        assert!(matches!(result, Err(PasswordPolicyError::TooShort { .. })));
    }

    #[test]
    fn common_long_password_is_rejected_for_weak_score() {
        // Assez long, mais un motif très commun et prévisible : le score
        // zxcvbn doit rester sous le seuil.
        let p = pwd("passwordpassword123");
        let assessment = assess_password(&p);
        assert!(assessment.meets_min_length);
        assert!(
            !assessment.meets_score_threshold,
            "score obtenu : {}",
            assessment.score
        );

        let result = validate_new_password(&p, &p);
        assert!(matches!(result, Err(PasswordPolicyError::TooWeak { .. })));
    }

    #[test]
    fn long_random_password_is_accepted() {
        let p = pwd("xK9$mQ2vL7#pR4wZ8!nB");
        let assessment = assess_password(&p);
        assert!(assessment.meets_min_length);
        assert!(
            assessment.meets_score_threshold,
            "score obtenu : {}",
            assessment.score
        );

        let result = validate_new_password(&p, &p);
        assert!(result.is_ok());
    }

    #[test]
    fn confirmation_mismatch_is_detected_even_with_strong_password() {
        let p1 = pwd("xK9$mQ2vL7#pR4wZ8!nB");
        let p2 = pwd("xK9$mQ2vL7#pR4wZ8!nC"); // dernier caractère différent
        let result = validate_new_password(&p1, &p2);
        assert!(matches!(
            result,
            Err(PasswordPolicyError::ConfirmationMismatch)
        ));
    }

    #[test]
    fn passwords_match_is_strict() {
        let p1 = pwd("MêmeMotDePasse123!");
        let p2 = pwd("MêmeMotDePasse123!");
        let p3 = pwd("mêmemotdepasse123!"); // casse différente
        assert!(passwords_match(&p1, &p2));
        assert!(!passwords_match(&p1, &p3));
    }

    #[test]
    fn score_labels_cover_full_range() {
        assert_eq!(score_label(0), "très faible");
        assert_eq!(score_label(1), "faible");
        assert_eq!(score_label(2), "moyen");
        assert_eq!(score_label(3), "fort");
        assert_eq!(score_label(4), "très fort");
    }

    #[test]
    fn assess_password_never_panics_on_edge_inputs() {
        // Robustesse basique : caractères unicode, emoji, chaîne très
        // longue ne doivent jamais faire paniquer l'évaluation (utilisée à
        // chaque frappe, F5 — une panique ici casserait l'UI en direct).
        for input in [
            "",
            " ",
            "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉",
            &"a".repeat(500),
            "mot de passe avec espaces et accents éàçù",
        ] {
            let p = pwd(input);
            let _ = assess_password(&p);
        }
    }
}
