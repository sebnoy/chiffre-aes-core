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
pub fn decompress_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
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
