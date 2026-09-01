//! Fuzz `extract_archive_with_limits` sur un flux d'archive arbitraire.
//!
//! Cible spécifiquement la logique de parsing d'archive interne (nombre
//! d'entrées, longueur/contenu des chemins, type fichier/dossier,
//! permissions, taille compressée déclarée, décompression) — la partie
//! du pipeline la plus riche en champs de longueur variable contrôlés par
//! l'entrée, donc la plus exposée aux erreurs de découpage/allocation.
//!
//! Volontairement testé indépendamment du chiffrement : dans le pipeline
//! réel, ce code ne s'exécute qu'après authentification GCM réussie, mais
//! `chiffre_aes_core` expose `extract_archive`/`extract_archive_with_limits`
//! comme fonctions publiques autonomes (utilisables par un intégrateur
//! qui gérerait le stockage/transport autrement) : elles doivent donc
//! être robustes face à une entrée arbitraire par elles-mêmes, sans
//! présumer qu'un appelant amont a déjà tout validé.
//!
//! Propriété recherchée : jamais de panic, quelle que soit l'entrée.

#![no_main]

use chiffre_aes_core::archive::{extract_archive_with_limits, ExtractionLimits};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };

    let mut cursor = Cursor::new(data);
    // Limites par défaut : c'est le chemin réellement emprunté en
    // pratique par le pipeline (voir pipeline.rs), donc celui qui doit
    // être le plus robuste.
    let _ = extract_archive_with_limits(&mut cursor, tmp.path(), ExtractionLimits::default());
});
