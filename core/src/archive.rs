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
//! - **Permissions** : le mode complet est stocké sous Unix à l'écriture,
//!   et **filtré** à l'extraction (voir [`sanitize_mode`]) — `setuid`,
//!   `setgid`, `sticky` et `other-write` sont toujours retirés, quel que
//!   soit le contenu de l'archive. Le bit exécutable, lui, est restauré
//!   par défaut (comportement historique nécessaire pour un usage normal
//!   de sauvegarde de ses propres fichiers), mais peut être désactivé via
//!   [`ExtractionLimits::preserve_executable_bit`] si l'archive peut
//!   provenir d'un tiers auquel le mot de passe a été partagé. Ce filtrage
//!   est nécessaire car l'authentification AEAD garantit l'origine de
//!   l'archive (quelqu'un connaissant le mot de passe), pas l'innocuité de
//!   ses métadonnées de permissions si ce tiers est malveillant. Ignorées
//!   à l'écriture/lecture sous les plateformes non-Unix (Windows).
//! - **Protection anti-évasion à l'extraction** : tout chemin relatif
//!   contenant `..`, un préfixe absolu, ou vide est rejeté (défense en
//!   profondeur, au cas où une archive proviendrait d'une source autre que
//!   ce logiciel — même si l'authentification AEAD garantit déjà que le
//!   contenu n'a pas été altéré après chiffrement par ce même logiciel).

use crate::compress::{compress_bytes, decompress_bytes_capped};
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
    #[error("chemin trop long pour le format d'archive (max 65535 octets UTF-8) : {0}")]
    PathTooLong(String),
    #[error("limite de ressources d'extraction dépassée : {0}")]
    LimitExceeded(String),
    #[error("archive corrompue ou mal formée")]
    Malformed,
}

/// A3 (durcissement) : limites de ressources appliquées lors de
/// l'extraction, indépendantes du contenu de l'archive elle-même —
/// protègent contre une archive authentique (mot de passe correct) mais
/// délibérément coûteuse à extraire (très grand nombre d'entrées, entrée
/// individuelle énorme, ou décompression totale disproportionnée).
#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    pub max_entries: u32,
    pub max_entry_compressed_size: u64,
    pub max_total_extracted_size: u64,
    /// Par défaut `true` : le bit exécutable stocké dans l'archive est
    /// restauré (comportement historique, nécessaire pour un usage normal
    /// de sauvegarde/restauration de ses propres fichiers — un script
    /// personnel chiffré doit rester exécutable après déchiffrement).
    /// `setuid`/`setgid`/`sticky`/`other-write` sont TOUJOURS retirés quelle
    /// que soit cette valeur, y compris lorsqu'elle est à `true` — voir
    /// [`sanitize_mode`]. Ne désactiver que si l'archive peut provenir d'un
    /// tiers auquel le mot de passe a été partagé sans confiance totale.
    pub preserve_executable_bit: bool,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_entry_compressed_size: 8 * 1024 * 1024 * 1024, // 8 Gio
            max_total_extracted_size: 100 * 1024 * 1024 * 1024, // 100 Gio
            preserve_executable_bit: true,
        }
    }
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
    // A1 (durcissement) : conversion vérifiée au lieu d'un cast silencieux
    // (`as u16` tronquait silencieusement un chemin trop long plutôt que de
    // le rejeter — un chemin de 65 537 octets aurait été stocké comme si sa
    // longueur était 1, désynchronisant la lecture de toutes les entrées
    // suivantes de l'archive).
    let path_len: u16 = path_bytes
        .len()
        .try_into()
        .map_err(|_| ArchiveError::PathTooLong(rel_path.to_string()))?;
    writer.write_all(&path_len.to_be_bytes())?;
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
/// interne lue depuis `reader`, sous `destination_dir`, avec les limites de
/// ressources par défaut ([`ExtractionLimits::default`]).
pub fn extract_archive<R: Read>(
    reader: &mut R,
    destination_dir: &Path,
) -> Result<Vec<ArchiveWarning>, ArchiveError> {
    extract_archive_with_limits(reader, destination_dir, ExtractionLimits::default())
}

/// Identique à [`extract_archive`], avec des limites de ressources
/// explicites — voir [`ExtractionLimits`].
pub fn extract_archive_with_limits<R: Read>(
    reader: &mut R,
    destination_dir: &Path,
    limits: ExtractionLimits,
) -> Result<Vec<ArchiveWarning>, ArchiveError> {
    let warnings = Vec::new();

    let mut count_buf = [0u8; 4];
    read_exact(reader, &mut count_buf)?;
    let count = u32::from_be_bytes(count_buf);

    // A3 (durcissement) : nombre d'entrées borné, vérifié avant toute
    // itération.
    if count > limits.max_entries {
        return Err(ArchiveError::LimitExceeded(format!(
            "nombre d'entrées ({count}) dépasse la limite autorisée ({})",
            limits.max_entries
        )));
    }

    fs::create_dir_all(destination_dir)?;

    let mut total_extracted: u64 = 0;

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
        let content_len_u64 = u64::from_be_bytes(size_buf);

        // A3 (durcissement) : taille compressée déclarée bornée AVANT toute
        // allocation — auparavant, `content_len` (entièrement contrôlé par
        // l'archive) était utilisé directement pour dimensionner un
        // `Vec`, ce qui permettait de déclencher une tentative
        // d'allocation massive rien qu'en mentant sur cette taille, avant
        // même que la lecture réelle ne commence.
        if content_len_u64 > limits.max_entry_compressed_size {
            return Err(ArchiveError::LimitExceeded(format!(
                "taille compressée déclarée pour {rel_path} ({content_len_u64} octets) dépasse la limite par entrée ({} octets)",
                limits.max_entry_compressed_size
            )));
        }
        let content_len = usize::try_from(content_len_u64).map_err(|_| ArchiveError::Malformed)?;

        let target_path = destination_dir.join(&safe_rel);

        if is_dir {
            fs::create_dir_all(&target_path)?;
            apply_permissions(&target_path, permissions, true, limits.preserve_executable_bit);
        } else {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let compressed = read_len_incrementally(reader, content_len)?;

            // A3 (durcissement) : la taille de sortie décompressée est
            // bornée par le budget total restant, pas seulement par une
            // constante fixe — empêche une succession de petites entrées
            // compressées de dépasser cumulativement la limite totale
            // même si chacune reste sous la limite par entrée.
            let remaining_budget = limits
                .max_total_extracted_size
                .saturating_sub(total_extracted);
            let remaining_budget_usize = usize::try_from(remaining_budget).unwrap_or(usize::MAX);
            let raw = decompress_bytes_capped(&compressed, remaining_budget_usize).map_err(
                |e| {
                    if e.kind() == io::ErrorKind::OutOfMemory {
                        ArchiveError::LimitExceeded(format!(
                            "taille totale extraite dépasserait la limite autorisée ({} octets) en traitant {rel_path}",
                            limits.max_total_extracted_size
                        ))
                    } else {
                        // Toute autre erreur de décodage (flux deflate
                        // réellement corrompu) reste distincte d'un simple
                        // dépassement de limite.
                        ArchiveError::Malformed
                    }
                },
            )?;
            total_extracted += raw.len() as u64;

            fs::write(&target_path, &raw)?;
            apply_permissions(&target_path, permissions, false, limits.preserve_executable_bit);
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

/// Taille des blocs de lecture incrémentale — voir [`read_len_incrementally`].
const READ_CHUNK_SIZE: usize = 64 * 1024;

/// Lit exactement `len` octets, **par blocs bornés**, plutôt que
/// d'allouer un `Vec` de `len` octets d'un seul coup avant de lire quoi
/// que ce soit.
///
/// `len` provient ici de `content_len`, un champ **déclaré par
/// l'archive elle-même** — donc entièrement contrôlé par un attaquant
/// potentiel. Il est certes borné par `ExtractionLimits::max_entry_compressed_size`
/// (8 Gio par défaut) avant l'appel, mais cette borne reste largement
/// suffisante pour un déni de service : une archive de quelques dizaines
/// d'octets déclarant une entrée proche de la limite déclenchait une
/// tentative d'allocation de plusieurs gigaoctets **avant même d'avoir
/// lu un seul octet du flux réel** — trouvé par fuzzing
/// (`fuzz/artifacts/extract_archive/oom-...`, une entrée de 24 octets
/// suffisait). En lisant par blocs, la mémoire réellement consommée suit
/// les octets **effectivement disponibles** dans le flux : si le flux
/// s'arrête avant `len`, `read_exact` échoue naturellement en ayant
/// alloué au plus quelques dizaines de kilooctets, jamais la valeur
/// déclarée.
fn read_len_incrementally<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, ArchiveError> {
    let mut buf = Vec::with_capacity(len.min(READ_CHUNK_SIZE));
    let mut remaining = len;
    let mut chunk = [0u8; READ_CHUNK_SIZE];
    while remaining > 0 {
        let to_read = remaining.min(READ_CHUNK_SIZE);
        read_exact(reader, &mut chunk[..to_read])?;
        buf.extend_from_slice(&chunk[..to_read]);
        remaining -= to_read;
    }
    Ok(buf)
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

/// Filtre les bits de mode issus d'une archive potentiellement hostile
/// avant application sur le disque.
///
/// L'authentification AEAD garantit que le contenu de l'archive n'a pas
/// été modifié par quelqu'un qui ne connaît pas le mot de passe — elle ne
/// garantit PAS que le champ « Permissions » d'une entrée est sûr à
/// restaurer tel quel. Si le mot de passe est partagé avec un tiers, ce
/// tiers peut produire une archive parfaitement authentique dont une
/// entrée déclare `0o4777` (setuid + rwx pour tous), ou rend exécutable un
/// fichier qui ne l'était pas à l'origine.
///
/// Cette fonction retire donc systématiquement, quoi que contienne
/// l'archive :
/// - `setuid` / `setgid` / `sticky` (jamais nécessaires pour un fichier ou
///   dossier personnel) ;
/// - le bit d'écriture « autres » (`other-write`) ;
/// - le bit exécutable sur les fichiers, sauf si explicitement désactivé
///   (voir [`ExtractionLimits::preserve_executable_bit`], `true` par
///   défaut pour préserver le comportement historique de sauvegarde de
///   ses propres fichiers — les dossiers restent toujours
///   traversables/exécutables, ce qui n'a pas la même portée de risque).
fn sanitize_mode(mode: u32, is_dir: bool, preserve_executable_bit: bool) -> u32 {
    const SETUID: u32 = 0o4000;
    const SETGID: u32 = 0o2000;
    const STICKY: u32 = 0o1000;
    const OTHER_WRITE: u32 = 0o002;
    const ALL_EXEC: u32 = 0o111;

    let cleaned = (mode & 0o777) & !(SETUID | SETGID | STICKY | OTHER_WRITE);
    if is_dir || preserve_executable_bit {
        cleaned
    } else {
        cleaned & !ALL_EXEC
    }
}

#[cfg(unix)]
fn apply_permissions(path: &Path, mode: u32, is_dir: bool, preserve_executable_bit: bool) {
    use std::os::unix::fs::PermissionsExt;
    let safe_mode = sanitize_mode(mode, is_dir, preserve_executable_bit);
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(safe_mode));
}

#[cfg(not(unix))]
fn apply_permissions(_path: &Path, _mode: u32, _is_dir: bool, _preserve_executable_bit: bool) {}

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

    // --- A1 (durcissement) : longueur de chemin ------------------------

    #[test]
    fn build_archive_rejects_path_longer_than_u16_max() {
        // Nom de chemin volontairement plus long que u16::MAX (65 535)
        // octets UTF-8 : write_entry doit rejeter explicitement plutôt que
        // de tronquer silencieusement sa longueur encodée. On utilise
        // `is_dir = true` pour ne pas dépendre d'un fichier réel sur
        // disque (le cas fichier partage le même point de contrôle, situé
        // avant toute lecture de contenu).
        let huge_name = "a".repeat(u16::MAX as usize + 1);
        let mut buf = Vec::new();
        let result = write_entry(&mut buf, &huge_name, Path::new("/inexistant"), true);
        assert!(matches!(result, Err(ArchiveError::PathTooLong(_))));
    }

    // --- A3 (durcissement) : limites de ressources à l'extraction ------

    #[test]
    fn extract_rejects_entry_count_above_limit() {
        let dest_dir = tempdir();
        let limits = ExtractionLimits {
            max_entries: 2,
            ..ExtractionLimits::default()
        };

        // Annonce 3 entrées alors que la limite autorisée est 2 : doit être
        // rejeté avant même de lire la première entrée.
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());

        let mut cursor = Cursor::new(buf);
        let result = extract_archive_with_limits(&mut cursor, &dest_dir, limits);
        assert!(matches!(result, Err(ArchiveError::LimitExceeded(_))));
    }

    #[test]
    fn extract_rejects_entry_compressed_size_above_limit() {
        let dest_dir = tempdir();
        let limits = ExtractionLimits {
            max_entry_compressed_size: 10,
            ..ExtractionLimits::default()
        };

        // Une entrée qui annonce une taille compressée (100 octets)
        // dépassant la limite par entrée (10 octets) doit être rejetée
        // AVANT toute tentative d'allocation à cette taille — on ne fournit
        // d'ailleurs délibérément aucun octet de contenu après l'en-tête
        // d'entrée : si le code tentait de lire le contenu avant de
        // vérifier la limite, ce test échouerait avec une erreur de
        // troncature plutôt que LimitExceeded, révélant l'ordre incorrect.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // 1 entrée
        let name = "gros_fichier.bin";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0); // type fichier
        buf.extend_from_slice(&0o644u32.to_be_bytes());
        buf.extend_from_slice(&100u64.to_be_bytes()); // taille compressée déclarée

        let mut cursor = Cursor::new(buf);
        let result = extract_archive_with_limits(&mut cursor, &dest_dir, limits);
        assert!(matches!(result, Err(ArchiveError::LimitExceeded(_))));
    }

    /// Régression pour un crash trouvé par fuzzing (`cargo fuzz run
    /// extract_archive`) : une entrée déclarant une taille compressée
    /// *sous* la limite de politique par entrée (donc qui passe le
    /// contrôle existant) mais très supérieure aux octets réellement
    /// fournis dans le flux ne doit jamais provoquer de tentative
    /// d'allocation à cette taille déclarée. Avant le correctif
    /// (allocation d'un `Vec` de `content_len` octets avant toute
    /// lecture), ce test à lui seul suffisait à faire crasher le
    /// processus par épuisement mémoire (OOM) sur une entrée artificielle
    /// de quelques dizaines d'octets, avec `max_entry_compressed_size`
    /// laissé à sa valeur par défaut (8 Gio).
    #[test]
    fn extract_does_not_allocate_declared_size_before_reading_actual_bytes() {
        let dest_dir = tempdir();

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // 1 entrée
        let name = "presque_vide.bin";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0); // type fichier
        buf.extend_from_slice(&0o644u32.to_be_bytes());
        // Sous la limite par défaut (8 Gio) : passe le contrôle de
        // politique. Aucun octet de contenu n'est fourni après ce champ.
        buf.extend_from_slice(&(2u64 * 1024 * 1024 * 1024).to_be_bytes());

        let mut cursor = Cursor::new(buf);
        // Doit échouer proprement (flux tronqué) — et non tenter d'abord
        // d'allouer ~2 Gio. Le test lui-même sert de garde-fou : s'il
        // recommence à allouer la taille déclarée, ce test redevient
        // le moyen le plus rapide de le remarquer (ralentissement ou
        // crash mémoire du processus de test), avant même un nouveau
        // passage de fuzzing.
        let result = extract_archive_with_limits(&mut cursor, &dest_dir, ExtractionLimits::default());
        assert!(
            matches!(result, Err(ArchiveError::Malformed) | Err(ArchiveError::Io(_))),
            "attendu une erreur de flux tronqué, obtenu {result:?}"
        );
    }

    #[test]
    fn extract_rejects_total_extracted_size_above_limit_decompression_bomb() {
        let dest_dir = tempdir();

        // Contenu hautement compressible (beaucoup de zéros) : une petite
        // entrée compressée qui se dilate largement une fois décompressée —
        // simule une bombe de décompression. On dérive la limite testée de
        // la taille compressée RÉELLEMENT obtenue plutôt que d'un seuil
        // fixe : le format deflate plafonne la longueur d'une
        // correspondance à 258 octets, donc même des données très
        // répétitives ne compressent pas à un ratio arbitrairement élevé
        // (un seuil fixe supposé "évidemment assez petit" peut donc se
        // révéler faux selon l'implémentation de compression utilisée).
        let huge_plain = vec![0u8; 10_000_000]; // 10 Mo de zéros
        let compressed = compress_bytes(&huge_plain).unwrap();
        assert!(
            (compressed.len() as u64) < huge_plain.len() as u64 / 10,
            "le contenu doit rester nettement plus compact compressé que décompressé pour ce test"
        );

        let limits = ExtractionLimits {
            // Nettement au-dessus de la taille compressée (n'échoue pas à
            // la vérification A3 par entrée), mais nettement en dessous de
            // la taille décompressée réelle (10 Mo) : isole précisément la
            // vérification de taille totale/décompression bombe testée
            // ici, indépendamment du ratio de compression exact obtenu.
            max_total_extracted_size: compressed.len() as u64 * 10,
            ..ExtractionLimits::default()
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        let name = "bombe.bin";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&0o644u32.to_be_bytes());
        buf.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
        buf.extend_from_slice(&compressed);

        let mut cursor = Cursor::new(buf);
        let result = extract_archive_with_limits(&mut cursor, &dest_dir, limits);
        assert!(matches!(result, Err(ArchiveError::LimitExceeded(_))));
        // Aucun fichier partiel ne doit rester visible comme un succès.
        assert!(!dest_dir.join("bombe.bin").exists()
            || fs::metadata(dest_dir.join("bombe.bin")).unwrap().len() <= 1000);
    }

    #[test]
    fn extract_reports_malformed_not_limit_exceeded_for_genuinely_corrupt_stream() {
        // Non-régression sur la distinction ErrorKind::OutOfMemory (limite
        // volontaire) vs autre erreur de décodage (flux réellement
        // corrompu) — voir compress::decompress_bytes_capped.
        let dest_dir = tempdir();

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        let name = "corrompu.bin";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&0o644u32.to_be_bytes());
        // Flux deflate valide au départ, puis corrompu par inversion de
        // bits sur plusieurs octets internes — bien plus fiable pour
        // garantir une erreur de décodage que des octets aléatoires purs
        // (qui pourraient occasionnellement former un flux "valide" par
        // hasard). Pas une histoire de taille : bien en-dessous de toute
        // limite configurée.
        let mut garbage = compress_bytes(&vec![0x55u8; 500]).unwrap();
        for b in garbage.iter_mut().skip(2).take(8) {
            *b ^= 0xFF;
        }
        buf.extend_from_slice(&(garbage.len() as u64).to_be_bytes());
        buf.extend_from_slice(&garbage);

        let mut cursor = Cursor::new(buf);
        let result = extract_archive(&mut cursor, &dest_dir);
        assert!(matches!(result, Err(ArchiveError::Malformed)));
    }

    // --- Permissions issues d'une archive hostile -----------------------

    #[cfg(unix)]
    #[test]
    fn extract_never_restores_setuid_or_other_write_even_with_executable_bit_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let dest_dir = tempdir();
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        let name = "innocent.txt";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0); // type fichier
        buf.extend_from_slice(&0o4777u32.to_be_bytes()); // setuid + rwx pour tous
        let content = compress_bytes(b"contenu").unwrap();
        buf.extend_from_slice(&(content.len() as u64).to_be_bytes());
        buf.extend_from_slice(&content);

        // Limites par défaut : preserve_executable_bit = true (comportement
        // historique). Même dans ce cas le plus permissif, setuid et
        // other-write ne doivent JAMAIS être restaurés.
        let mut cursor = Cursor::new(buf);
        extract_archive(&mut cursor, &dest_dir).unwrap();

        let mode = fs::metadata(dest_dir.join("innocent.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o4000, 0, "setuid ne doit jamais être restauré");
        assert_eq!(mode & 0o002, 0, "other-write ne doit jamais être restauré");
        // L'exécutable, lui, EST restauré par défaut (comportement
        // historique) — voir permissions_are_preserved pour la
        // non-régression correspondante sur un cas d'usage légitime.
        assert_ne!(
            mode & 0o100,
            0,
            "exécutable (owner) doit être restauré par défaut"
        );
    }

    #[cfg(unix)]
    #[test]
    fn extract_strips_executable_bit_when_explicitly_disabled() {
        use std::os::unix::fs::PermissionsExt;

        let dest_dir = tempdir();
        let limits = ExtractionLimits {
            preserve_executable_bit: false,
            ..ExtractionLimits::default()
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        let name = "innocent.txt";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&0o4777u32.to_be_bytes()); // setuid + rwx pour tous
        let content = compress_bytes(b"contenu").unwrap();
        buf.extend_from_slice(&(content.len() as u64).to_be_bytes());
        buf.extend_from_slice(&content);

        let mut cursor = Cursor::new(buf);
        extract_archive_with_limits(&mut cursor, &dest_dir, limits).unwrap();

        let mode = fs::metadata(dest_dir.join("innocent.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o4000, 0, "setuid ne doit jamais être restauré");
        assert_eq!(mode & 0o002, 0, "other-write ne doit jamais être restauré");
        assert_eq!(
            mode & 0o111,
            0,
            "exécutable ne doit pas être restauré quand preserve_executable_bit=false"
        );
    }

    #[cfg(unix)]
    #[test]
    fn extract_preserves_executable_bit_only_when_explicitly_requested() {
        use std::os::unix::fs::PermissionsExt;

        let dest_dir = tempdir();
        let limits = ExtractionLimits {
            preserve_executable_bit: true,
            ..ExtractionLimits::default()
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        let name = "script.sh";
        buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&0o4755u32.to_be_bytes()); // setuid + rwxr-xr-x
        let content = compress_bytes(b"#!/bin/sh\necho ok\n").unwrap();
        buf.extend_from_slice(&(content.len() as u64).to_be_bytes());
        buf.extend_from_slice(&content);

        let mut cursor = Cursor::new(buf);
        extract_archive_with_limits(&mut cursor, &dest_dir, limits).unwrap();

        let mode = fs::metadata(dest_dir.join("script.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o4000, 0, "setuid ne doit JAMAIS être restauré, même avec preserve_executable_bit");
        assert_ne!(mode & 0o100, 0, "exécutable (owner) doit être restauré ici, explicitement demandé");
    }

    #[test]
    fn extract_with_default_limits_still_accepts_normal_archive() {
        // Non-régression : les limites par défaut ne doivent pas gêner un
        // usage normal (roundtrip déjà couvert ailleurs, on vérifie ici
        // juste que ExtractionLimits::default() n'est pas trop restrictif
        // pour un cas simple).
        let src_dir = tempdir();
        let dest_dir = tempdir();
        fs::write(src_dir.join("normal.txt"), b"contenu tout a fait normal").unwrap();

        let selected = vec![src_dir.join("normal.txt")];
        let mut buf = Vec::new();
        build_archive(&selected, &mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        extract_archive_with_limits(&mut cursor, &dest_dir, ExtractionLimits::default()).unwrap();

        assert_eq!(
            fs::read(dest_dir.join("normal.txt")).unwrap(),
            b"contenu tout a fait normal"
        );
    }
}
