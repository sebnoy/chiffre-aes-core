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
//!
//! # P1.4 (durcissement, suite à revue externe) : atomicité de l'extraction
//!
//! `format::decrypt_file` est déjà atomique au niveau du fichier `.enc`
//! (temp + rename, voir ci-dessus). Mais l'étape suivante — désarchiver
//! l'archive intermédiaire vers `destination_dir` — écrivait auparavant
//! directement dans `destination_dir` au fur et à mesure de la boucle
//! d'extraction : une erreur sur l'entrée N (limite de ressources
//! dépassée, entrée malformée, disque plein...) laissait alors les
//! entrées 0..N-1 déjà présentes dans `destination_dir`, sans nettoyage.
//!
//! `decrypt_to_dir_with_progress` désarchive désormais vers un dossier
//! temporaire (créé à côté de `destination_dir`, donc sur le même système
//! de fichiers) et ne le bascule vers `destination_dir` qu'une fois
//! l'extraction *entièrement* réussie. En cas d'échec à n'importe quelle
//! étape, ce dossier temporaire est supprimé et `destination_dir` n'est
//! jamais modifié.
//!
//! Cas particulier : si `destination_dir` existe déjà (et contient déjà
//! des fichiers, par exemple une extraction précédente ou un dossier
//! choisi manuellement par l'utilisateur), la bascule finale consiste à
//! déplacer chaque entrée de premier niveau une par une plutôt qu'un
//! unique renommage — voir [`finalize_extraction`] pour le détail et la
//! limite résiduelle de ce cas.

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

    // P1.4 : on désarchive vers un dossier temporaire plutôt que
    // directement vers `destination_dir` — voir la doc de module
    // ci-dessus. `tmp_extract_dir` (TempDir) est supprimé automatiquement
    // à la sortie de portée (y compris via le `?` ci-dessous en cas
    // d'erreur d'extraction) tant que `finalize_extraction` n'a pas réussi.
    let tmp_extract_dir =
        create_tmp_extract_dir(destination_dir).map_err(ArchiveError::Io)?;

    let extracted = (|| -> Result<Vec<ArchiveWarning>, ArchiveError> {
        let file = File::open(&tmp_archive)?;
        let mut reader = BufReader::new(file);
        extract_archive(&mut reader, tmp_extract_dir.path())
    })()?;

    // Extraction complète et réussie : on ne bascule vers la destination
    // finale qu'à partir d'ici. `destination_dir` n'a été touché à aucun
    // moment avant cette ligne.
    finalize_extraction(tmp_extract_dir, destination_dir)?;

    Ok(extracted)
}

/// Crée un dossier temporaire vide, dans le même répertoire parent que
/// `destination_dir` (garantit un `rename` atomique sur le même système de
/// fichiers lors de la finalisation), avec un nom non prévisible — même
/// principe que [`format::create_tmp_path`] pour les fichiers temporaires.
///
/// Le [`tempfile::TempDir`] retourné supprime récursivement son contenu à
/// sa destruction (RAII), y compris en cas de `panic!`, tant que
/// [`finalize_extraction`] n'a pas explicitement pris la main dessus.
fn create_tmp_extract_dir(destination_dir: &Path) -> std::io::Result<tempfile::TempDir> {
    let parent = match destination_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // Le répertoire parent doit exister pour pouvoir y créer un dossier
    // temporaire sœur de `destination_dir` (qui, lui, peut ne pas encore
    // exister : c'est justement le cas nominal d'une extraction vers un
    // nouveau dossier).
    std::fs::create_dir_all(parent)?;
    tempfile::Builder::new()
        .prefix(".chiffre-aes-extract-tmp-")
        .rand_bytes(16)
        .tempdir_in(parent)
}

/// Bascule le contenu entièrement extrait de `tmp_dir` vers
/// `destination_dir`, de façon atomique lorsque c'est possible.
///
/// - Si `destination_dir` **n'existe pas encore** (cas nominal : extraction
///   vers un nouveau dossier) : un unique `rename` du dossier temporaire
///   vers `destination_dir` — atomique sur un même système de fichiers, ce
///   qui est garanti par [`create_tmp_extract_dir`] (dossier temporaire
///   créé comme sœur de `destination_dir`).
/// - Si `destination_dir` **existe déjà** (dossier choisi par l'utilisateur
///   ou réutilisé) : un `rename` séparé pour chaque entrée de premier
///   niveau du dossier temporaire vers `destination_dir`. Ce cas n'est pas
///   entièrement atomique : si l'un de ces renommages échoue (par exemple
///   parce qu'une entrée de même nom existe déjà à destination), les
///   entrées déjà déplacées avant l'échec resteront dans `destination_dir`.
///   C'est une limite résiduelle, mais très réduite par rapport au
///   comportement précédent : elle ne peut plus se produire pendant la
///   phase de désarchivage/décompression elle-même (la partie longue et la
///   plus susceptible d'échouer), seulement pendant cette fusion finale,
///   rapide et purement locale.
fn finalize_extraction(
    tmp_dir: tempfile::TempDir,
    destination_dir: &Path,
) -> Result<(), ArchiveError> {
    if !destination_dir.exists() {
        std::fs::rename(tmp_dir.path(), destination_dir)?;
        // Le dossier a été déplacé : il n'existe plus à son emplacement
        // temporaire d'origine. On désactive le nettoyage automatique du
        // `TempDir` (qui, sinon, tenterait de supprimer un chemin qui
        // n'existe plus lors de son `Drop` — sans conséquence pratique,
        // mais autant être explicite sur le fait que la responsabilité a
        // changé de main). `keep()` remplace `into_path()` (dépréciée)
        // depuis `tempfile` 3.14.
        let _ = tmp_dir.keep();
        return Ok(());
    }

    // `destination_dir` existe déjà : fusion entrée par entrée (voir
    // limite documentée ci-dessus). `tmp_dir` reste géré par son `Drop`
    // pendant toute cette boucle : si une entrée échoue à se déplacer, les
    // entrées restantes (non encore déplacées) sont supprimées avec le
    // reste du dossier temporaire à la sortie de cette fonction.
    for entry in std::fs::read_dir(tmp_dir.path())? {
        let entry = entry?;
        let target = destination_dir.join(entry.file_name());
        std::fs::rename(entry.path(), &target)?;
    }

    Ok(())
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

    // --- P1.4 (durcissement, suite à revue externe) : atomicité de
    // l'extraction ------------------------------------------------------

    #[test]
    fn decrypt_to_dir_creates_absent_destination_via_atomic_rename() {
        // Couvre la branche "destination_dir n'existe pas encore" de
        // `finalize_extraction` : contrairement au helper `tempdir()`
        // ci-dessus (qui crée le dossier), `dest` n'est ici qu'un chemin,
        // jamais créé avant l'appel à `decrypt_to_dir`.
        let src = tempdir();
        let dest_parent = tempdir();
        let dest = dest_parent.join("nouveau_dossier_jamais_cree");
        assert!(!dest.exists());

        fs::write(src.join("f.txt"), b"contenu atomique").unwrap();
        let enc_path = src.join("f.enc");
        let password = Zeroizing::new("mot-de-passe-dest-absente".to_string());

        encrypt_paths(&[src.join("f.txt")], &enc_path, &password, small_params()).unwrap();
        decrypt_to_dir(&enc_path, &dest, &password).unwrap();

        assert!(dest.exists(), "la destination aurait dû être créée");
        assert_eq!(fs::read(dest.join("f.txt")).unwrap(), b"contenu atomique");

        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn extraction_failure_leaves_absent_destination_untouched() {
        // Test au niveau des fonctions de base utilisées par
        // `decrypt_to_dir_with_progress` (contournement volontaire de la
        // couche crypto : une archive corrompue au niveau AAD/GCM échoue
        // de toute façon avant même d'atteindre l'étape d'extraction —
        // c'est justement l'étape d'extraction elle-même, une fois
        // l'authentification passée, que ce test cible).
        //
        // Scénario : une archive interne valide de 2 entrées est tronquée
        // au milieu du contenu de la seconde, pour que `extract_archive`
        // réussisse la première entrée (déjà écrite dans le dossier
        // temporaire) puis échoue sur la seconde. `destination_dir` ne
        // doit alors jamais être créé.
        let src = tempdir();
        let dest_parent = tempdir();
        let dest = dest_parent.join("destination_qui_ne_doit_pas_exister");
        assert!(!dest.exists());

        fs::write(src.join("a.txt"), vec![b'A'; 4096]).unwrap();
        fs::write(src.join("b.txt"), vec![b'B'; 4096]).unwrap();

        let mut raw_archive = Vec::new();
        let (count, warnings) =
            build_archive(&[src.join("a.txt"), src.join("b.txt")], &mut raw_archive).unwrap();
        assert_eq!(count, 2);
        assert!(warnings.is_empty());

        // Troncature volontaire : on coupe l'archive bien avant sa fin
        // (dans le contenu de la seconde entrée), ce qui déclenche
        // `ArchiveError::Malformed` (EOF inattendue) une fois la première
        // entrée déjà traitée.
        let truncated_len = raw_archive.len() - 16;
        raw_archive.truncate(truncated_len);

        let tmp_extract_dir = create_tmp_extract_dir(&dest).unwrap();
        let mut cursor = std::io::Cursor::new(raw_archive);
        let result = extract_archive(&mut cursor, tmp_extract_dir.path());

        assert!(
            matches!(result, Err(ArchiveError::Malformed) | Err(ArchiveError::Io(_))),
            "l'extraction aurait dû échouer sur l'archive tronquée, résultat : {result:?}"
        );

        // On ne finalise jamais (comme le ferait decrypt_to_dir_with_progress
        // en cas d'erreur) : le dossier temporaire est laissé tel quel et
        // sera supprimé à sa sortie de portée ci-dessous.
        assert!(
            !dest.exists(),
            "destination_dir n'aurait jamais dû être créé après un échec d'extraction"
        );

        drop(tmp_extract_dir);
        assert!(!dest.exists());
    }
}
