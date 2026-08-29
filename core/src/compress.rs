//! Compression / décompression.
//!
//! Backend Deflate pur Rust (`flate2`, feature `rust_backend` = `miniz_oxide`),
//! sans dépendance C dynamique — cohérent avec la contrainte de binaires
//! statiques. `zstd` avait été envisagé comme premier choix, mais ce repli
//! reste tout à fait valable en pratique.
//!
//! Ordre des traitements retenu : **compression individuelle de chaque
//! fichier, puis archivage** du résultat (voir `archive.rs`) — et non
//! l'inverse. Ce module opère donc sur le contenu d'un fichier à la fois.

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{self, Read, Write};

/// Compresse `data` intégralement et retourne le résultat.
///
/// Note : le format d'archive exige d'écrire la taille du contenu
/// **avant** le contenu lui-même, ce qui impose de connaître la taille
/// compressée à l'avance — d'où un passage en mémoire ici plutôt qu'un
/// flux direct fichier-vers-fichier. Limitation connue pour des fichiers
/// individuels extrêmement volumineux (voir README).
pub fn compress_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Décompresse un buffer produit par [`compress_bytes`].
///
/// Sans limite de taille de sortie — réservé à un usage interne/tests où
/// l'entrée est de confiance. Pour toute décompression de données pouvant
/// provenir d'un tiers (extraction d'archive), utiliser
/// [`decompress_bytes_capped`].
pub fn decompress_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
    decompress_bytes_capped(data, usize::MAX)
}

/// A3 (durcissement) : identique à [`decompress_bytes`], mais échoue dès
/// que la sortie dépasserait `max_len` octets, **sans jamais allouer
/// au-delà** de cette limite — protection contre une "décompression bombe"
/// (flux compressé compact se dilatant en sortie à une taille
/// disproportionnée).
pub fn decompress_bytes_capped(data: &[u8], max_len: usize) -> io::Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_len {
            // `OutOfMemory` sert ici de marqueur distinctif : l'appelant
            // (archive.rs) peut ainsi distinguer un dépassement de limite
            // volontaire d'une véritable erreur de décodage (flux
            // compressé corrompu), sans confondre les deux causes dans le
            // message d'erreur remonté à l'utilisateur.
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "sortie décompressée dépasse la limite autorisée (décompression bombe suspectée)",
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_compress_decompress() {
        let original = b"AAAAAAAAAABBBBBBBBBBCCCCCCCCCC contenu repetitif compressible";
        let compressed = compress_bytes(original).unwrap();
        let restored = decompress_bytes(&compressed).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn roundtrip_empty_input() {
        let compressed = compress_bytes(b"").unwrap();
        let restored = decompress_bytes(&compressed).unwrap();
        assert_eq!(restored, b"");
    }

    #[test]
    fn compression_actually_reduces_size_for_repetitive_data() {
        let original = vec![b'A'; 100_000];
        let compressed = compress_bytes(&original).unwrap();
        assert!(compressed.len() < original.len() / 10);
    }
}
