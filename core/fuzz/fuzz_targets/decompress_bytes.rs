//! Fuzz `decompress_bytes_capped` isolément, sans passer par le format
//! d'archive complet.
//!
//! Objectif : isoler la robustesse du décodeur Deflate (`flate2`,
//! backend `miniz_oxide`, pur Rust) lui-même — un flux compressé
//! corrompu ou adverse est le type d'entrée le plus "hostile au format"
//! de tout le pipeline, puisqu'il ne suit aucune structure de haut niveau
//! (contrairement au header ou à l'archive) que l'on pourrait valider
//! avant de commencer à décoder.
//!
//! Propriété recherchée : jamais de panic, et surtout — vérifiée
//! explicitement ici, contrairement aux deux autres harnais — la sortie
//! ne doit JAMAIS dépasser le plafond demandé, quelle que soit l'entrée.
//! C'est la garantie anti-"décompression bombe" : si elle était violée,
//! ce ne serait pas seulement un panic mais une vraie fuite de la
//! protection de ressources documentée dans FORMAT.md §8.

#![no_main]

use chiffre_aes_core::compress::decompress_bytes_capped;
use libfuzzer_sys::fuzz_target;

// Plafond volontairement petit : force le décodeur à interrompre le
// décodage en plein flux dans un grand nombre de cas générés par le
// fuzzer, ce qui est précisément le chemin de code (arrêt anticipé) le
// moins exercé par les tests unitaires existants.
const MAX_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if let Ok(out) = decompress_bytes_capped(data, MAX_LEN) {
        assert!(
            out.len() <= MAX_LEN,
            "violation du plafond de décompression : {} > {}",
            out.len(),
            MAX_LEN
        );
    }
    // Une erreur (flux invalide ou plafond atteint) est un résultat normal
    // et attendu ; seul un panic ou la violation ci-dessus constituent un
    // signal pour libFuzzer.
});
