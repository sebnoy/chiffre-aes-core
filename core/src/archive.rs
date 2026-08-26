//! Archive interne, avant chiffrement.
//!
//! ```text
//! [Nombre d'entrées : u32]
//! Pour chaque entrée :
//!   [Longueur chemin relatif : u16][Chemin relatif UTF-8]
//!   [Type : 1 octet]  (0 = fichier, 1 = dossier)
//!   [Permissions : u32]
//!   [Taille du contenu : u64]  (0 pour un dossier)
//!   [Contenu brut]              (si fichier)
//! ```
//!
//! Le contenu de chaque fichier est **déjà compressé** au moment où il est
//! écrit dans l'archive (compression avant archivage) : le champ « Taille
//! du contenu » est donc la taille compressée, et « Contenu brut » désigne
//! les octets tels qu'écrits dans l'archive (compressés), pas le contenu
//! original.
//!
//! Décisions de gestion des cas limites :
//! - **Liens symboliques** : non suivis, ignorés avec un avertissement
//!   (évite les boucles et les évasions hors du périmètre sélectionné).
//! - **Chemins non-UTF8** : ignorés avec un avertissement (le format
//!   n'admet que des chemins UTF-8).
//! - **Fichiers vides** : supportés nativement (taille de contenu = 0).
//! - **Chemins Unicode** : supportés (le nom de fichier est stocké tel
//!   quel en UTF-8).
//! - **Permissions** : préservées sous Unix (mode complet) ; ignorées à
//!   l'écriture/lecture sous les plateformes non-Unix (Windows), la
//!   valeur stockée y est alors indicative uniquement.
//! - **Protection anti-évasion à l'extraction** : tout chemin relatif
//!   contenant `..`, un préfixe absolu, ou vide est rejeté (défense en
//!   profondeur, au cas où une archive proviendrait d'une source autre que
//!   ce logiciel — même si l'authentification AEAD garantit déjà que le
//!   contenu n'a pas été altéré après chiffrement par ce même logiciel).

use crate::compress::{compress_bytes, decompress_bytes};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// Avertissement non bloquant survenu pendant l'archivage ou l'extraction
/// (élément ignoré plutôt que de faire échouer toute l'opération).
#[derive(Debug, Clone)]
pub struct ArchiveWarning {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("erreur système : {0}")]
    Io(#[from] io::Error),
    #[error("chemin non sûr dans l'archive (absolu, vide, ou tentative d'évasion) : {0}")]
    UnsafePath(String),
    #[error("archive corrompue ou mal formée")]
    Malformed,
}

/// Construit l'archive interne à partir d'une liste de chemins
/// sélectionnés (fichiers et/ou dossiers) et l'écrit dans `writer`.
///
/// Chaque dossier sélectionné est parcouru récursivement ; son nom devient
/// la racine des chemins relatifs de son contenu (ex. sélectionner
/// `/home/alice/photos` produit des entrées `photos/`, `photos/img1.jpg`,
/// `photos/2024/vacances.jpg`, ...).
///
/// Retourne le nombre d'entrées écrites et la liste des avertissements
/// (éléments ignorés) rencontrés.
pub fn build_archive<W: Write>(
    selected_paths: &[PathBuf],
    writer: &mut W,
) -> Result<(u32, Vec<ArchiveWarning>), ArchiveError> {
    let mut warnings = Vec::new();
    let mut entries: Vec<(String, PathBuf, bool)> = Vec::new();

    for selected in selected_paths {
        let meta = match fs::symlink_metadata(selected) {
            Ok(m) => m,
            Err(e) => {
                warnings.push(ArchiveWarning {
                    path: selected.clone(),
                    reason: format!("inaccessible : {e}"),
                });
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            warnings.push(ArchiveWarning {
                path: selected.clone(),
                reason: "lien symbolique ignoré (non suivi)".to_string(),
            });
            continue;
        }

        let name = match selected.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => {
                warnings.push(ArchiveWarning {
                    path: selected.clone(),
                    reason: "nom de fichier non-UTF8, ignoré".to_string(),
                });
                continue;
            }
        };

        if meta.is_dir() {
            entries.push((name.clone(), selected.clone(), true));
            walk_dir(selected, &name, &mut entries, &mut warnings)?;
        } else {
            entries.push((name, selected.clone(), false));
        }
    }

    writer.write_all(&(entries.len() as u32).to_be_bytes())?;
    for (rel_path, abs_path, is_dir) in &entries {
        write_entry(writer, rel_path, abs_path, *is_dir)?;
    }

    Ok((entries.len() as u32, warnings))
}

fn walk_dir(
    dir_abs: &Path,
    rel_prefix: &str,
    entries: &mut Vec<(String, PathBuf, bool)>,
    warnings: &mut Vec<ArchiveWarning>,
) -> Result<(), ArchiveError> {
    let mut children: Vec<_> = fs::read_dir(dir_abs)?.collect::<Result<_, _>>()?;
    // Ordre déterministe (utile pour les tests et la reproductibilité).
    children.sort_by_key(|e| e.file_name());

    for child in children {
        let child_path = child.path();
        let meta = match fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => {
                warnings.push(ArchiveWarning {
                    path: child_path.clone(),
                    reason: format!("inaccessible : {e}"),
                });
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            warnings.push(ArchiveWarning {
                path: child_path.clone(),
                reason: "lien symbolique ignoré (non suivi)".to_string(),
            });
            continue;
        }

        let name = match child_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => {
                warnings.push(ArchiveWarning {
                    path: child_path.clone(),
                    reason: "nom de fichier non-UTF8, ignoré".to_string(),
                });
                continue;
            }
        };

        let rel = format!("{rel_prefix}/{name}");
        if meta.is_dir() {
            entries.push((rel.clone(), child_path.clone(), true));
            walk_dir(&child_path, &rel, entries, warnings)?;
        } else {
            entries.push((rel, child_path, false));
        }
    }

    Ok(())
}

fn write_entry<W: Write>(
    writer: &mut W,
    rel_path: &str,
    abs_path: &Path,
    is_dir: bool,
) -> Result<(), ArchiveError> {
    let path_bytes = rel_path.as_bytes();
    writer.write_all(&(path_bytes.len() as u16).to_be_bytes())?;
    writer.write_all(path_bytes)?;
    writer.write_all(&[if is_dir { 1 } else { 0 }])?;

    let permissions = read_permissions(abs_path);
    writer.write_all(&permissions.to_be_bytes())?;

    if is_dir {
        writer.write_all(&0u64.to_be_bytes())?;
    } else {
        // Chargement en mémoire nécessaire ici : le format exige d'écrire
        // la taille compressée AVANT le contenu, donc la compression doit
        // être terminée avant de connaître cette taille. Limitation connue
        // pour des fichiers individuels extrêmement volumineux (voir
        // README) — la contrainte de streaming s'applique au chiffrement
        // final, qui reste strictement par blocs de 1 Mo quel que soit ce
        // qui précède.
        let raw = fs::read(abs_path)?;
        let compressed = compress_bytes(&raw)?;
        writer.write_all(&(compressed.len() as u64).to_be_bytes())?;
        writer.write_all(&compressed)?;
    }

    Ok(())
}

/// Reconstruit les fichiers/dossiers d'origine à partir d'une archive
/// interne lue depuis `reader`, sous `destination_dir`.
pub fn extract_archive<R: Read>(
    reader: &mut R,
    destination_dir: &Path,
) -> Result<Vec<ArchiveWarning>, ArchiveError> {
    let warnings = Vec::new();

    let mut count_buf = [0u8; 4];
    read_exact(reader, &mut count_buf)?;
    let count = u32::from_be_bytes(count_buf);

    fs::create_dir_all(destination_dir)?;

    for _ in 0..count {
        let mut len_buf = [0u8; 2];
        read_exact(reader, &mut len_buf)?;
        let path_len = u16::from_be_bytes(len_buf) as usize;

        let mut path_bytes = vec![0u8; path_len];
        read_exact(reader, &mut path_bytes)?;
        let rel_path = String::from_utf8(path_bytes).map_err(|_| ArchiveError::Malformed)?;
        let safe_rel = validate_relative_path(&rel_path)?;

        let mut type_buf = [0u8; 1];
        read_exact(reader, &mut type_buf)?;
        let is_dir = match type_buf[0] {
            0 => false,
            1 => true,
            _ => return Err(ArchiveError::Malformed),
        };

        let mut perm_buf = [0u8; 4];
        read_exact(reader, &mut perm_buf)?;
        let permissions = u32::from_be_bytes(perm_buf);

        let mut size_buf = [0u8; 8];
        read_exact(reader, &mut size_buf)?;
        let content_len = usize::try_from(u64::from_be_bytes(size_buf))
            .map_err(|_| ArchiveError::Malformed)?;

        let target_path = destination_dir.join(&safe_rel);

        if is_dir {
            fs::create_dir_all(&target_path)?;
            apply_permissions(&target_path, permissions);
        } else {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut compressed = vec![0u8; content_len];
            read_exact(reader, &mut compressed)?;
            let raw = decompress_bytes(&compressed).map_err(|_| ArchiveError::Malformed)?;
            fs::write(&target_path, &raw)?;
            apply_permissions(&target_path, permissions);
        }
    }

    Ok(warnings)
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), ArchiveError> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ArchiveError::Malformed
        } else {
            ArchiveError::Io(e)
        }
    })
}

/// Rejette tout chemin relatif absolu, vide, ou contenant une remontée
/// (`..`) — défense en profondeur contre une archive malformée qui tenterait
/// d'écrire en dehors du dossier de destination (cf. commentaire de module).
fn validate_relative_path(rel: &str) -> Result<PathBuf, ArchiveError> {
    if rel.is_empty() {
        return Err(ArchiveError::UnsafePath(rel.to_string()));
    }
    let path = Path::new(rel);
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => return Err(ArchiveError::UnsafePath(rel.to_string())),
        }
    }
    Ok(path.to_path_buf())
}

#[cfg(unix)]
fn read_permissions(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o644)
}

#[cfg(not(unix))]
fn read_permissions(_path: &Path) -> u32 {
    0o644
}

#[cfg(unix)]
fn apply_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn apply_permissions(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;

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
            "chiffre_aes_core_archive_test_{}_{}",
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

    fn hash_file(path: &Path) -> [u8; 32] {
        Sha256::digest(fs::read(path).unwrap()).into()
    }

    /// Construit une petite arborescence de test avec sous-dossiers,
    /// fichier vide, et nom de fichier Unicode.
    fn build_sample_tree(root: &Path) -> Vec<PathBuf> {
        fs::create_dir_all(root.join("dossier/sous-dossier")).unwrap();
        fs::write(root.join("dossier/a.txt"), b"contenu du fichier a").unwrap();
        fs::write(
            root.join("dossier/sous-dossier/b.txt"),
            b"contenu du fichier b, un peu plus long pour tester la compression AAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        fs::write(root.join("dossier/vide.txt"), b"").unwrap();
        fs::write(root.join("dossier/étoile-éàç.txt"), "contenu unicode : café, mañana, 日本語").unwrap();
        vec![root.join("dossier")]
    }

    #[test]
    fn roundtrip_directory_tree_by_hash() {
        let src_dir = tempdir();
        let dest_dir = tempdir();
        let selected = build_sample_tree(&src_dir);

        let mut buf = Vec::new();
        let (count, warnings) = build_archive(&selected, &mut buf).unwrap();
        assert_eq!(count, 6); // dossier + sous-dossier + a.txt + b.txt + vide.txt + unicode.txt
        assert!(warnings.is_empty());

        let mut cursor = Cursor::new(buf);
        let extract_warnings = extract_archive(&mut cursor, &dest_dir).unwrap();
        assert!(extract_warnings.is_empty());

        for rel in [
            "dossier/a.txt",
            "dossier/sous-dossier/b.txt",
            "dossier/vide.txt",
            "dossier/étoile-éàç.txt",
        ] {
            let original = src_dir.join(rel);
            let restored = dest_dir.join(rel);
            assert!(restored.exists(), "manquant : {rel}");
            assert_eq!(
                hash_file(&original),
                hash_file(&restored),
                "hash différent pour {rel}"
            );
        }
        assert!(dest_dir.join("dossier/sous-dossier").is_dir());
    }

    #[test]
    fn roundtrip_mixed_files_and_folders_selection() {
        let src_dir = tempdir();
        let dest_dir = tempdir();

        fs::write(src_dir.join("isole.txt"), b"fichier isole hors dossier").unwrap();
        fs::create_dir_all(src_dir.join("sous")).unwrap();
        fs::write(src_dir.join("sous/interne.txt"), b"fichier dans un dossier").unwrap();

        let selected = vec![src_dir.join("isole.txt"), src_dir.join("sous")];
        let mut buf = Vec::new();
        build_archive(&selected, &mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        extract_archive(&mut cursor, &dest_dir).unwrap();

        assert_eq!(
            hash_file(&src_dir.join("isole.txt")),
            hash_file(&dest_dir.join("isole.txt"))
        );
        assert_eq!(
            hash_file(&src_dir.join("sous/interne.txt")),
            hash_file(&dest_dir.join("sous/interne.txt"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn symlink_is_skipped_with_warning() {
        use std::os::unix::fs::symlink;
        let src_dir = tempdir();
        let dest_dir = tempdir();

        fs::write(src_dir.join("reel.txt"), b"cible reelle").unwrap();
        symlink(src_dir.join("reel.txt"), src_dir.join("lien.txt")).unwrap();

        let selected = vec![src_dir.join("reel.txt"), src_dir.join("lien.txt")];
        let mut buf = Vec::new();
        let (count, warnings) = build_archive(&selected, &mut buf).unwrap();

        assert_eq!(count, 1, "seul le fichier réel doit être archivé");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].reason.contains("lien symbolique"));

        let mut cursor = Cursor::new(buf);
        extract_archive(&mut cursor, &dest_dir).unwrap();
        assert!(dest_dir.join("reel.txt").exists());
        assert!(!dest_dir.join("lien.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn permissions_are_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let src_dir = tempdir();
        let dest_dir = tempdir();

        let file_path = src_dir.join("executable.sh");
        fs::write(&file_path, b"#!/bin/sh\necho hello\n").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o750)).unwrap();

        let selected = vec![file_path.clone()];
        let mut buf = Vec::new();
        build_archive(&selected, &mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        extract_archive(&mut cursor, &dest_dir).unwrap();

        let restored_mode = fs::metadata(dest_dir.join("executable.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(restored_mode, 0o750);
    }

    #[test]
    fn extract_rejects_path_traversal_attempt() {
        let dest_dir = tempdir();

        // Construit à la main une archive malveillante avec un chemin
        // contenant une remontée de répertoire.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // 1 entrée
        let evil_path = "../evasion.txt";
        buf.extend_from_slice(&(evil_path.len() as u16).to_be_bytes());
        buf.extend_from_slice(evil_path.as_bytes());
        buf.push(0); // type fichier
        buf.extend_from_slice(&0o644u32.to_be_bytes());
        let content = compress_bytes(b"contenu").unwrap();
        buf.extend_from_slice(&(content.len() as u64).to_be_bytes());
        buf.extend_from_slice(&content);

        let mut cursor = Cursor::new(buf);
        let result = extract_archive(&mut cursor, &dest_dir);
        assert!(matches!(result, Err(ArchiveError::UnsafePath(_))));
    }

    #[test]
    fn empty_file_roundtrip() {
        let src_dir = tempdir();
        let dest_dir = tempdir();
        fs::write(src_dir.join("rien.txt"), b"").unwrap();

        let selected = vec![src_dir.join("rien.txt")];
        let mut buf = Vec::new();
        build_archive(&selected, &mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        extract_archive(&mut cursor, &dest_dir).unwrap();

        assert_eq!(fs::read(dest_dir.join("rien.txt")).unwrap(), Vec::<u8>::new());
    }
}
