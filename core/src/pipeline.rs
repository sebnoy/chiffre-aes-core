//! Assemble `archive.rs` (+ `compress.rs`, appelé depuis `archive.rs`) et
//! `format.rs` pour offrir les deux opérations de haut niveau attendues par
//! l'UI : chiffrer une sélection de fichiers/dossiers vers un `.enc`, et
//! déchiffrer un `.enc` vers un dossier de destination.
//!
//! Étant donné que le format `.enc` exige de connaître la taille totale des
//! données en clair **avant** d'écrire l'en-tête, et que cette taille n'est
//! pas connue à l'avance une fois la compression/l'archivage pris en
//! compte, l'archive complète est d'abord construite dans un fichier
//! temporaire, qui est ensuite passé tel quel à `format::encrypt_file`.
//! Symétriquement au déchiffrement : `format::decrypt_file` produit
//! d'abord un fichier temporaire (l'archive), qui est ensuite désarchivé.
//! Le fichier temporaire est systématiquement supprimé en fin d'opération,
//! y compris en cas d'erreur.

use crate::archive::{build_archive, extract_archive, ArchiveError, ArchiveWarning};
use crate::crypto::{Argon2Params, Password};
use crate::format::{self, FormatError, ProgressUpdate};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
}

/// Chiffre la sélection de fichiers/dossiers `selected_paths` vers
/// `output_enc`. Retourne les avertissements non bloquants survenus lors de
/// l'archivage (ex. liens symboliques ignorés).
pub fn encrypt_paths(
    selected_paths: &[PathBuf],
    output_enc: &Path,
    password: &Password,
    params: Argon2Params,
) -> Result<Vec<ArchiveWarning>, PipelineError> {
    encrypt_paths_with_progress(selected_paths, output_enc, password, params, &mut |_| true)
}

/// Identique à [`encrypt_paths`], avec un rapport d'avancement chunk par
/// chunk pendant la phase de chiffrement. La phase d'archivage (rapide, en
/// amont) ne produit pas d'avancement détaillé.
pub fn encrypt_paths_with_progress(
    selected_paths: &[PathBuf],
    output_enc: &Path,
    password: &Password,
    params: Argon2Params,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<Vec<ArchiveWarning>, PipelineError> {
    // A4 (durcissement) : voir format::create_tmp_path. `tmp_archive`
    // (TempPath) est supprimé automatiquement à la sortie de portée — quel
    // que soit le point de sortie de cette fonction (succès, `?` sur une
    // erreur, ou même un panic) — donc plus besoin de nettoyage manuel à
    // chaque point de sortie comme avant.
    let tmp_archive = format::create_tmp_path(output_enc).map_err(ArchiveError::Io)?;

    let warnings = (|| -> Result<Vec<ArchiveWarning>, ArchiveError> {
        let file = File::create(&tmp_archive)?;
        let mut writer = BufWriter::new(file);
        let (_, warnings) = build_archive(selected_paths, &mut writer)?;
        use std::io::Write;
        writer.flush()?;
        Ok(warnings)
    })()?;

    format::encrypt_file_with_progress(&tmp_archive, output_enc, password, params, on_progress)?;

    Ok(warnings)
}

/// Déchiffre `input_enc` et restitue les fichiers/dossiers d'origine sous
/// `destination_dir`. Retourne les avertissements non bloquants (le cas
/// échéant).
pub fn decrypt_to_dir(
    input_enc: &Path,
    destination_dir: &Path,
    password: &Password,
) -> Result<Vec<ArchiveWarning>, PipelineError> {
    decrypt_to_dir_with_progress(input_enc, destination_dir, password, &mut |_| true)
}

/// Identique à [`decrypt_to_dir`], avec un rapport d'avancement chunk par
/// chunk pendant la phase de déchiffrement, symétrique à
/// [`encrypt_paths_with_progress`]. Le désarchivage qui suit (rapide,
/// purement local) ne produit pas d'avancement détaillé.
pub fn decrypt_to_dir_with_progress(
    input_enc: &Path,
    destination_dir: &Path,
    password: &Password,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<Vec<ArchiveWarning>, PipelineError> {
    // A4 (durcissement) : voir format::create_tmp_path et le commentaire
    // équivalent dans encrypt_paths_with_progress ci-dessus.
    let tmp_archive = format::create_tmp_path(input_enc).map_err(ArchiveError::Io)?;

    format::decrypt_file_with_progress(input_enc, &tmp_archive, password, on_progress)?;

    let extracted = (|| -> Result<Vec<ArchiveWarning>, ArchiveError> {
        let file = File::open(&tmp_archive)?;
        let mut reader = BufReader::new(file);
        extract_archive(&mut reader, destination_dir)
    })()?;

    Ok(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use zeroize::Zeroizing;

    struct TempDir(PathBuf);
    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "chiffre_aes_core_pipeline_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn small_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn hash_file(path: &Path) -> [u8; 32] {
        Sha256::digest(fs::read(path).unwrap()).into()
    }

    #[test]
    fn full_pipeline_roundtrip_folder() {
        let src = tempdir();
        let dest = tempdir();

        fs::create_dir_all(src.join("projet/docs")).unwrap();
        fs::write(src.join("projet/readme.txt"), b"lisez-moi").unwrap();
        fs::write(
            src.join("projet/docs/notes.txt"),
            "des notes avec accents : éàê, et un peu de répétition AAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        fs::write(src.join("projet/vide.bin"), b"").unwrap();

        let enc_path = src.join("projet.enc");
        let password = Zeroizing::new("mot-de-passe-pipeline-complet".to_string());

        let warnings = encrypt_paths(
            &[src.join("projet")],
            &enc_path,
            &password,
            small_params(),
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert!(enc_path.exists());

        let extract_warnings = decrypt_to_dir(&enc_path, &dest, &password).unwrap();
        assert!(extract_warnings.is_empty());

        for rel in ["projet/readme.txt", "projet/docs/notes.txt", "projet/vide.bin"] {
            assert_eq!(
                hash_file(&src.join(rel)),
                hash_file(&dest.join(rel)),
                "hash différent pour {rel}"
            );
        }
    }

    #[test]
    fn full_pipeline_wrong_password_creates_nothing() {
        let src = tempdir();
        let dest = tempdir();
        fs::write(src.join("secret.txt"), b"contenu confidentiel").unwrap();

        let enc_path = src.join("secret.enc");
        let good = Zeroizing::new("bon-mot-de-passe-pipeline".to_string());
        let bad = Zeroizing::new("mauvais-mot-de-passe-pipeline".to_string());

        encrypt_paths(&[src.join("secret.txt")], &enc_path, &good, small_params()).unwrap();

        let result = decrypt_to_dir(&enc_path, &dest, &bad);
        assert!(matches!(
            result,
            Err(PipelineError::Format(FormatError::WrongPassword))
        ));
        assert!(
            fs::read_dir(&*dest).unwrap().next().is_none(),
            "aucun fichier ne doit être extrait en cas de mauvais mot de passe"
        );
    }

    #[test]
    fn no_temp_archive_left_behind_after_success() {
        let src = tempdir();
        let dest = tempdir();
        fs::write(src.join("f.txt"), b"contenu").unwrap();
        let enc_path = src.join("f.enc");
        let password = Zeroizing::new("mot-de-passe-nettoyage-tmp".to_string());

        encrypt_paths(&[src.join("f.txt")], &enc_path, &password, small_params()).unwrap();
        decrypt_to_dir(&enc_path, &dest, &password).unwrap();

        // Seuls f.txt (source) et f.enc (résultat) doivent subsister dans
        // src ; aucun fichier temporaire (archive intermédiaire côté
        // chiffrement, ou tout autre résidu) ne doit traîner — nettoyage
        // RAII via TempPath, voir format::create_tmp_path.
        let mut remaining: Vec<_> = fs::read_dir(&*src)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        remaining.sort();
        assert_eq!(remaining, vec!["f.enc".to_string(), "f.txt".to_string()]);
    }
}
