//! Format de fichier propriétaire `.enc`.
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  EN-TÊTE (clair, mais authentifié)           │
//! ├─────────────────────────────────────────────┤
//! │  CHUNK 0 chiffré (1 Mo) + tag d'authentif.   │
//! │  CHUNK 1 chiffré (1 Mo) + tag d'authentif.   │
//! │  ...                                          │
//! │  CHUNK N (dernier, marqué explicitement)      │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! Ce module travaille sur des fichiers réels sur disque. Il ne connaît pas
//! la notion d'archive multi-fichiers ni de compression : `encrypt_file` /
//! `decrypt_file` opèrent sur un unique fichier d'entrée / de sortie,
//! considéré comme "les données en clair" au sens du format (le flux
//! compressé + archivé produit par `archive.rs`/`compress.rs`, le cas
//! échéant).

use crate::crypto::{
    decrypt_buffer, derive_key, encrypt_buffer, generate_base_nonce, generate_salt,
    Argon2Params, CryptoError, DerivedKey, Nonce, Password, NONCE_LEN, SALT_LEN, TAG_LEN,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use tempfile::TempPath;

/// Identifiant du format ("magic"), 4 octets.
pub const MAGIC: &[u8; 4] = b"ENC1";
/// Version du format (permet des évolutions futures).
pub const FORMAT_VERSION: u8 = 1;
/// Taille de chunk par défaut : 1 Mo.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// M2 (durcissement) : bornes de politique sur `chunk_size`, indépendantes
/// du fichier. `MIN` évite un nombre de chunks absurde pour une taille
/// totale donnée (chaque chunk a un coût fixe : nonce dérivé, AAD,
/// allocation) ; `MAX` reste cohérent avec `DEFAULT_CHUNK_SIZE` tout en
/// laissant de la marge pour d'éventuels réglages futurs.
pub const MIN_CHUNK_SIZE: u32 = 1024; // 1 Kio
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024; // 64 Mio

/// Taille de l'en-tête sérialisé, hors tag d'authentification.
/// 4 (magic) + 1 (version) + 16 (sel) + 9 (params argon2) + 12 (nonce base)
/// + 4 (taille de chunk) + 8 (nb chunks) + 8 (taille totale en clair).
pub const HEADER_FIXED_LEN: usize = 4 + 1 + SALT_LEN + 9 + NONCE_LEN + 4 + 8 + 8;

/// Compteur réservé pour dériver le nonce servant à l'authentification de
/// l'en-tête, distinct de l'espace des compteurs de chunks de données
/// (0..total_chunks-1), qui ne peut pratiquement jamais l'atteindre.
const HEADER_NONCE_COUNTER: u64 = u64::MAX;

/// Erreurs du format `.enc`, volontairement distinguées : le code appelant
/// (CLI, GUI) peut ainsi afficher un message adapté
/// ("mot de passe incorrect" vs "fichier corrompu / altéré" vs "erreur
/// système") sans confondre ces trois natures d'échec.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("mot de passe incorrect")]
    WrongPassword,

    #[error("fichier corrompu ou altéré")]
    Corrupted,

    #[error("fichier tronqué (données manquantes)")]
    Truncated,

    #[error("en-tête invalide (magic ou version incompatible)")]
    InvalidHeader,

    #[error("erreur système : {0}")]
    Io(#[from] io::Error),

    #[error("erreur cryptographique interne : {0}")]
    Crypto(#[from] CryptoError),

    #[error("opération annulée")]
    Cancelled,
}

/// Avancement d'une opération de chiffrement, transmis chunk par chunk
/// (permet une barre de progression réelle, avec retour d'avancement
/// après chaque chunk traité).
#[derive(Debug, Clone, Copy)]
pub struct ProgressUpdate {
    /// Index du chunk qui vient d'être traité (0-based).
    pub chunk_index: u64,
    /// Nombre total de chunks de l'opération.
    pub total_chunks: u64,
    /// Octets (en clair) traités jusqu'ici.
    pub bytes_done: u64,
    /// Octets (en clair) total à traiter.
    pub bytes_total: u64,
}

impl ProgressUpdate {
    pub fn percent(&self) -> u8 {
        if self.bytes_total == 0 {
            100
        } else {
            ((self.bytes_done as f64 / self.bytes_total as f64) * 100.0).round() as u8
        }
    }
}

/// En-tête du fichier `.enc`.
#[derive(Debug, Clone)]
pub struct Header {
    pub salt: [u8; SALT_LEN],
    pub argon2_params: Argon2Params,
    pub base_nonce: [u8; NONCE_LEN],
    pub chunk_size: u32,
    pub total_chunks: u64,
    pub total_plaintext_size: u64,
}

impl Header {
    /// Sérialise les champs fixes de l'en-tête (hors tag), toujours dans le
    /// même ordre. Longueur toujours égale à `HEADER_FIXED_LEN`.
    fn to_bytes(&self) -> [u8; HEADER_FIXED_LEN] {
        let mut buf = [0u8; HEADER_FIXED_LEN];
        let mut pos = 0;

        buf[pos..pos + 4].copy_from_slice(MAGIC);
        pos += 4;
        buf[pos] = FORMAT_VERSION;
        pos += 1;
        buf[pos..pos + SALT_LEN].copy_from_slice(&self.salt);
        pos += SALT_LEN;
        buf[pos..pos + 4].copy_from_slice(&self.argon2_params.memory_kib.to_be_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.argon2_params.iterations.to_be_bytes());
        pos += 4;
        buf[pos] = self.argon2_params.parallelism;
        pos += 1;
        buf[pos..pos + NONCE_LEN].copy_from_slice(&self.base_nonce);
        pos += NONCE_LEN;
        buf[pos..pos + 4].copy_from_slice(&self.chunk_size.to_be_bytes());
        pos += 4;
        buf[pos..pos + 8].copy_from_slice(&self.total_chunks.to_be_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.total_plaintext_size.to_be_bytes());
        pos += 8;

        debug_assert_eq!(pos, HEADER_FIXED_LEN);
        buf
    }

    /// Désérialise l'en-tête à partir d'un buffer de longueur
    /// `HEADER_FIXED_LEN`. Vérifie le magic et la version.
    fn from_bytes(buf: &[u8; HEADER_FIXED_LEN]) -> Result<Self, FormatError> {
        let mut pos = 0;

        if &buf[pos..pos + 4] != MAGIC {
            return Err(FormatError::InvalidHeader);
        }
        pos += 4;

        let version = buf[pos];
        pos += 1;
        if version != FORMAT_VERSION {
            return Err(FormatError::InvalidHeader);
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[pos..pos + SALT_LEN]);
        pos += SALT_LEN;

        let memory_kib = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let iterations = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let parallelism = buf[pos];
        pos += 1;

        let mut base_nonce = [0u8; NONCE_LEN];
        base_nonce.copy_from_slice(&buf[pos..pos + NONCE_LEN]);
        pos += NONCE_LEN;

        let chunk_size = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let total_chunks = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let total_plaintext_size = u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;

        debug_assert_eq!(pos, HEADER_FIXED_LEN);

        if chunk_size == 0 {
            return Err(FormatError::InvalidHeader);
        }
        // M2 (durcissement) : bornes de chunk_size indépendantes du fichier.
        if chunk_size < MIN_CHUNK_SIZE || chunk_size > MAX_CHUNK_SIZE {
            return Err(FormatError::InvalidHeader);
        }

        // M2 (durcissement) : cohérence total_chunks / total_plaintext_size
        // / chunk_size — N == ceil(S / C) pour S > 0, N == 1 pour S == 0
        // (un fichier vide produit malgré tout un chunk vide, voir
        // `encrypt_file_with_progress`). Arithmétique `checked_*` de bout
        // en bout : un dépassement lors du calcul est traité comme un
        // en-tête invalide plutôt que de paniquer ou de boucler.
        let expected_total_chunks: u64 = if total_plaintext_size == 0 {
            1
        } else {
            let chunk_size_u64 = chunk_size as u64;
            // ceil(S / C) = (S + C - 1) / C, en évitant tout dépassement.
            let numerator = total_plaintext_size
                .checked_add(chunk_size_u64)
                .and_then(|v| v.checked_sub(1))
                .ok_or(FormatError::InvalidHeader)?;
            numerator / chunk_size_u64
        };
        if total_chunks != expected_total_chunks {
            return Err(FormatError::InvalidHeader);
        }
        // Garde-fou supplémentaire : chunk_size (u64) * total_chunks ne doit
        // pas déborder — utilisé ailleurs (expected_plaintext_len) pour
        // localiser un chunk ; un dépassement silencieux y serait dangereux.
        (chunk_size as u64)
            .checked_mul(total_chunks)
            .ok_or(FormatError::InvalidHeader)?;

        Ok(Header {
            salt,
            argon2_params: Argon2Params {
                memory_kib,
                iterations,
                parallelism,
            },
            base_nonce,
            chunk_size,
            total_chunks,
            total_plaintext_size,
        })
    }
}

/// Dérive le nonce d'un chunk (ou de l'en-tête, via `HEADER_NONCE_COUNTER`)
/// à partir du nonce de base : XOR du compteur (u64) sur les 8 derniers
/// octets du nonce de 12 octets.
fn derive_nonce(base_nonce: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base_nonce;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..8 {
        nonce[NONCE_LEN - 8 + i] ^= counter_bytes[i];
    }
    nonce
}

/// AAD d'un chunk de données : `hash(en-tête complet) || index || flag_dernier`
/// — empêche réordonnancement, duplication, mélange entre archives.
fn chunk_aad(header_hash: &[u8; 32], index: u64, is_last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 1);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(if is_last { 1 } else { 0 });
    aad
}

/// Calcule la taille de texte clair attendue pour le chunk `index`, étant
/// donné la taille totale et la taille de chunk déclarées dans l'en-tête.
fn expected_plaintext_len(header: &Header, index: u64) -> u64 {
    let chunk_size = header.chunk_size as u64;
    if header.total_chunks == 0 {
        return 0;
    }
    if index + 1 < header.total_chunks {
        chunk_size
    } else {
        // Dernier chunk : reste après tous les chunks pleins précédents.
        header
            .total_plaintext_size
            .saturating_sub(chunk_size * index)
    }
}

/// Chiffre le fichier `input_path` vers `output_path` au format `.enc`.
///
/// Écrit d'abord vers un fichier temporaire, puis **relit et vérifie
/// l'intégrité de ce qui vient d'être écrit avant de finaliser**, en
/// renommant le temporaire vers la destination définitive. En cas
/// d'échec à n'importe quelle étape, le fichier temporaire est supprimé et
/// aucune trace ne subsiste (le fichier `output_path` n'est jamais créé
/// partiellement).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &Password,
    params: Argon2Params,
) -> Result<(), FormatError> {
    encrypt_file_with_progress(input_path, output_path, password, params, &mut |_| true)
}

/// Identique à [`encrypt_file`], avec un rapport d'avancement chunk par
/// chunk.
///
/// `on_progress` est appelé après chaque chunk écrit (pendant la phase
/// d'écriture uniquement ; la phase de vérification post-écriture reste
/// silencieuse — elle est rapide et purement interne). Il doit
/// retourner `true` pour continuer, ou `false` pour annuler proprement
/// l'opération (le fichier temporaire est alors supprimé, aucune trace ne
/// subsiste, comme pour toute autre erreur).
pub fn encrypt_file_with_progress(
    input_path: &Path,
    output_path: &Path,
    password: &Password,
    params: Argon2Params,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<(), FormatError> {
    let input_size = fs::metadata(input_path)?.len();
    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    let total_chunks = if input_size == 0 {
        1 // un fichier vide produit malgré tout un chunk (vide) explicitement marqué "dernier".
    } else {
        input_size.div_ceil(chunk_size)
    };

    let salt = generate_salt();
    let base_nonce = generate_base_nonce();
    let key = derive_key(password, &salt, params)?;

    let header = Header {
        salt,
        argon2_params: params,
        base_nonce,
        chunk_size: DEFAULT_CHUNK_SIZE,
        total_chunks,
        total_plaintext_size: input_size,
    };

    let tmp_path = create_tmp_path(output_path)?;

    let result = (|| -> Result<(), FormatError> {
        write_encrypted(input_path, &tmp_path, &header, &key, on_progress)?;
        verify_encrypted(&tmp_path, password)?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            tmp_path
                .persist(output_path)
                .map_err(|e| FormatError::Io(e.error))?;
            Ok(())
        }
        // `tmp_path` (TempPath) est automatiquement supprimé ici à la sortie
        // de portée (RAII) — plus de nettoyage manuel nécessaire, et ça
        // fonctionne même si une étape ci-dessus panique.
        Err(e) => Err(e),
    }
}

fn write_encrypted(
    input_path: &Path,
    tmp_output_path: &Path,
    header: &Header,
    key: &DerivedKey,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<(), FormatError> {
    let header_bytes = header.to_bytes();
    let header_nonce = derive_nonce(&header.base_nonce, HEADER_NONCE_COUNTER);
    let header_tag = encrypt_buffer(key, Nonce::from_raw_unchecked(header_nonce), &[], &header_bytes)?;
    debug_assert_eq!(header_tag.len(), TAG_LEN);

    let mut header_hash_input = Vec::with_capacity(HEADER_FIXED_LEN + TAG_LEN);
    header_hash_input.extend_from_slice(&header_bytes);
    header_hash_input.extend_from_slice(&header_tag);
    let header_hash: [u8; 32] = Sha256::digest(&header_hash_input).into();

    let in_file = File::open(input_path)?;
    let mut reader = BufReader::with_capacity(header.chunk_size as usize, in_file);

    let out_file = File::create(tmp_output_path)?;
    let mut writer = BufWriter::new(out_file);

    writer.write_all(&header_bytes)?;
    writer.write_all(&header_tag)?;

    let mut buf = vec![0u8; header.chunk_size as usize];
    let mut index: u64 = 0;
    let mut bytes_done: u64 = 0;

    loop {
        let is_last_by_count = index + 1 >= header.total_chunks;
        let want = expected_plaintext_len(header, index) as usize;

        // Lecture exacte de `want` octets (0 possible pour un fichier vide).
        let mut filled = 0;
        while filled < want {
            let n = reader.read(&mut buf[filled..want])?;
            if n == 0 {
                // Le fichier source a changé/rétréci pendant l'opération.
                return Err(FormatError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "le fichier source est plus court que sa taille initiale",
                )));
            }
            filled += n;
        }

        let is_last = is_last_by_count;
        let nonce = derive_nonce(&header.base_nonce, index);
        let aad = chunk_aad(&header_hash, index, is_last);
        let ciphertext = encrypt_buffer(key, Nonce::from_raw_unchecked(nonce), &buf[..want], &aad)?;
        writer.write_all(&ciphertext)?;

        bytes_done += want as u64;
        let keep_going = on_progress(ProgressUpdate {
            chunk_index: index,
            total_chunks: header.total_chunks,
            bytes_done,
            bytes_total: header.total_plaintext_size,
        });
        if !keep_going {
            return Err(FormatError::Cancelled);
        }

        if is_last {
            break;
        }
        index += 1;
    }

    writer.flush()?;
    Ok(())
}

/// Relit intégralement le fichier chiffré `path` et vérifie que toutes les
/// données s'authentifient correctement, sans rien écrire sur disque
/// (utilisé juste après l'écriture, en vérification d'intégrité avant
/// toute écriture définitive).
fn verify_encrypted(path: &Path, password: &Password) -> Result<(), FormatError> {
    decrypt_stream(path, password, &mut io::sink(), &mut |_| true)
}

/// Déchiffre `input_path` (`.enc`) vers `output_path`.
///
/// Rien n'est finalisé/déplacé vers la destination définitive tant que la
/// totalité de l'archive n'est pas validée : on écrit vers un fichier
/// temporaire, et seule une vérification complète réussie déclenche le
/// renommage vers `output_path`.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &Password,
) -> Result<(), FormatError> {
    decrypt_file_with_progress(input_path, output_path, password, &mut |_| true)
}

/// Identique à [`decrypt_file`], avec un rapport d'avancement chunk par
/// chunk, symétrique à [`encrypt_file_with_progress`]. Mêmes garanties :
/// `on_progress` retourne `false` pour annuler proprement (nettoyage
/// garanti, aucune trace résiduelle).
pub fn decrypt_file_with_progress(
    input_path: &Path,
    output_path: &Path,
    password: &Password,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<(), FormatError> {
    let tmp_path = create_tmp_path(output_path)?;

    let result = (|| -> Result<(), FormatError> {
        let out_file = File::create(&tmp_path)?;
        let mut writer = BufWriter::new(out_file);
        decrypt_stream(input_path, password, &mut writer, on_progress)?;
        writer.flush()?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            tmp_path
                .persist(output_path)
                .map_err(|e| FormatError::Io(e.error))?;
            Ok(())
        }
        // Nettoyage RAII automatique, voir create_tmp_path.
        Err(e) => Err(e),
    }
}

/// Cœur commun du déchiffrement : lit l'en-tête, l'authentifie, puis
/// déchiffre chaque chunk en écrivant vers `sink`. Utilisé à la fois par
/// `decrypt_file` (écriture réelle) et `verify_encrypted` (écriture vers
/// `io::sink()`, aucune trace sur disque — dans ce dernier cas la
/// progression n'est pas rapportée, `verify_encrypted` passe un callback
/// neutre).
fn decrypt_stream<W: Write>(
    input_path: &Path,
    password: &Password,
    sink: &mut W,
    on_progress: &mut dyn FnMut(ProgressUpdate) -> bool,
) -> Result<(), FormatError> {
    let in_file = File::open(input_path)?;
    let mut reader = BufReader::new(in_file);

    let mut header_buf = [0u8; HEADER_FIXED_LEN];
    read_exact_or(&mut reader, &mut header_buf, FormatError::Truncated)?;
    let header = Header::from_bytes(&header_buf)?;

    let mut header_tag = [0u8; TAG_LEN];
    read_exact_or(&mut reader, &mut header_tag, FormatError::Truncated)?;

    let key = derive_key(password, &header.salt, header.argon2_params)?;

    // Authentification de l'en-tête AVANT tout le reste. Un échec ici
    // signifie très probablement un mot de passe incorrect, et non des
    // données altérées.
    let header_nonce = derive_nonce(&header.base_nonce, HEADER_NONCE_COUNTER);
    decrypt_buffer(&key, Nonce::from_raw_unchecked(header_nonce), &header_tag, &header_buf)
        .map_err(|_| FormatError::WrongPassword)?;

    let mut header_hash_input = Vec::with_capacity(HEADER_FIXED_LEN + TAG_LEN);
    header_hash_input.extend_from_slice(&header_buf);
    header_hash_input.extend_from_slice(&header_tag);
    let header_hash: [u8; 32] = Sha256::digest(&header_hash_input).into();

    let mut total_written: u64 = 0;
    let mut index: u64 = 0;
    let chunk_size = header.chunk_size as usize;
    let mut cipher_buf = vec![0u8; chunk_size + TAG_LEN];

    // Cas particulier : total_chunks == 0 n'est pas un en-tête valide produit
    // par ce logiciel (un fichier vide produit tout de même 1 chunk vide),
    // mais on le traite comme "aucune donnée" plutôt que de planter.
    while index < header.total_chunks {
        let is_last = index + 1 >= header.total_chunks;
        let want_plain = expected_plaintext_len(&header, index) as usize;
        let want_cipher = want_plain + TAG_LEN;

        let n_read = read_up_to(&mut reader, &mut cipher_buf[..want_cipher])?;
        if n_read < want_cipher {
            // Pas assez d'octets pour ce chunk : fichier tronqué.
            return Err(FormatError::Truncated);
        }

        let aad = chunk_aad(&header_hash, index, is_last);
        let nonce = derive_nonce(&header.base_nonce, index);
        let plaintext = decrypt_buffer(&key, Nonce::from_raw_unchecked(nonce), &cipher_buf[..want_cipher], &aad)
            .map_err(|_| FormatError::Corrupted)?;

        sink.write_all(&plaintext)?;
        total_written += plaintext.len() as u64;

        let keep_going = on_progress(ProgressUpdate {
            chunk_index: index,
            total_chunks: header.total_chunks,
            bytes_done: total_written,
            bytes_total: header.total_plaintext_size,
        });
        if !keep_going {
            return Err(FormatError::Cancelled);
        }

        index += 1;
    }

    // Contrôle qu'il ne reste aucun octet supplémentaire après le dernier
    // chunk attendu (détection de troncature "inversée" / ajout de données,
    // et protection contre les attaques de troncature combinées à un ajout).
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(FormatError::Corrupted);
    }

    // Cohérence taille totale déclarée vs obtenue (détection de troncature,
    // y compris si le nombre de chunks était correct mais que la taille
    // totale déclarée ne correspond pas aux données réellement produites).
    if total_written != header.total_plaintext_size {
        return Err(FormatError::Truncated);
    }

    Ok(())
}

/// Lit exactement `buf.len()` octets, ou retourne `on_eof` si le flux est
/// plus court (fichier tronqué au niveau de l'en-tête).
fn read_exact_or<R: Read>(reader: &mut R, buf: &mut [u8], on_eof: FormatError) -> Result<(), FormatError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(on_eof);
        }
        filled += n;
    }
    Ok(())
}

/// Lit au maximum `buf.len()` octets, en essayant de le remplir totalement
/// tant que le flux fournit des données ; retourne le nombre d'octets
/// effectivement lus (peut être `< buf.len()` en fin de flux, sans erreur).
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, io::Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// A4 (durcissement) : crée un fichier temporaire de façon sécurisée dans
/// le même répertoire que `output_path` (garantit un `rename` atomique sur
/// le même système de fichiers à la fin de l'opération), avec un nom
/// **non prévisible** et une création atomique (`O_EXCL` sous-jacent via
/// la crate `tempfile`) — élimine la fenêtre de course qu'un nom fixe
/// comme l'ancien `.tmp-in-progress` pouvait ouvrir (collision, lien
/// symbolique posé à l'avance par un autre processus).
///
/// Retourne un [`TempPath`] : le fichier est automatiquement supprimé à la
/// sortie de portée (RAII), y compris en cas de `panic!` — remplace le
/// nettoyage manuel (`fs::remove_file`) qui n'aurait pas été exécuté dans
/// ce dernier cas. Utiliser `.persist(output_path)` pour le renommer vers
/// sa destination finale en cas de succès (consomme le `TempPath`, aucune
/// suppression n'a alors lieu).
pub(crate) fn create_tmp_path(output_path: &Path) -> io::Result<TempPath> {
    let parent = match output_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let named = tempfile::Builder::new()
        .prefix(".chiffre-aes-tmp-")
        .rand_bytes(16)
        .tempfile_in(parent)?;
    Ok(named.into_temp_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn pwd(s: &str) -> Password {
        Zeroizing::new(s.to_string())
    }

    fn write_temp_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    fn small_params() -> Argon2Params {
        // Paramètres Argon2id allégés pour accélérer les tests (le format
        // et les seuils par défaut de production restent inchangés).
        Argon2Params {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn roundtrip_small_file() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "plain.txt", b"Hello, monde ! Contenu de test.");
        let enc = dir.join("plain.txt.enc");
        let decrypted = dir.join("plain.txt.out");

        let password = pwd("un-mot-de-passe-de-test-solide");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();
        decrypt_file(&enc, &decrypted, &password).unwrap();

        let original = fs::read(&input).unwrap();
        let restored = fs::read(&decrypted).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_empty_file() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "empty.bin", b"");
        let enc = dir.join("empty.bin.enc");
        let decrypted = dir.join("empty.bin.out");

        let password = pwd("mot-de-passe-fichier-vide-123");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();
        decrypt_file(&enc, &decrypted, &password).unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_multi_chunk_file() {
        let dir = tempdir();
        // Utilise un chunk_size par défaut de 1 Mo ; on force plusieurs
        // chunks avec ~2.5 Mo de données pseudo-aléatoires déterministes.
        let mut content = vec![0u8; 2_684_354 /* ~2.56 Mo, dernier chunk partiel */];
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let input = write_temp_file(&dir, "big.bin", &content);
        let enc = dir.join("big.bin.enc");
        let decrypted = dir.join("big.bin.out");

        let password = pwd("mot-de-passe-multi-chunk-xyz");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();
        decrypt_file(&enc, &decrypted, &password).unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), content);
    }

    #[test]
    fn decrypt_fails_with_wrong_password_before_writing_anything() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "secret.txt", b"donnee confidentielle");
        let enc = dir.join("secret.txt.enc");
        let decrypted = dir.join("secret.txt.out");

        encrypt_file(&input, &enc, &pwd("bon-mot-de-passe-ici"), small_params()).unwrap();

        let result = decrypt_file(&enc, &decrypted, &pwd("mauvais-mot-de-passe"));
        assert!(matches!(result, Err(FormatError::WrongPassword)));
        assert!(!decrypted.exists(), "aucun fichier ne doit être créé en cas d'échec");
    }

    #[test]
    fn decrypt_fails_on_corrupted_chunk() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "data.txt", &vec![b'X'; 5000]);
        let enc = dir.join("data.txt.enc");
        let decrypted = dir.join("data.txt.out");
        let password = pwd("mot-de-passe-corruption-test");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        // On altère un octet dans la zone des données chiffrées (après
        // l'en-tête + son tag), pour simuler une corruption du fichier.
        let mut bytes = fs::read(&enc).unwrap();
        let corrupt_pos = HEADER_FIXED_LEN + TAG_LEN + 10;
        bytes[corrupt_pos] ^= 0xFF;
        fs::write(&enc, &bytes).unwrap();

        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_fails_on_truncated_file() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "data2.txt", &vec![b'Y'; 5000]);
        let enc = dir.join("data2.txt.enc");
        let decrypted = dir.join("data2.txt.out");
        let password = pwd("mot-de-passe-troncature-test");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let bytes = fs::read(&enc).unwrap();
        let truncated = &bytes[..bytes.len() - 5]; // retire les 5 derniers octets (tag partiel)
        fs::write(&enc, truncated).unwrap();

        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Truncated)));
        assert!(!decrypted.exists());
    }

    /// Construit un fichier `.enc` valide à bas niveau (2 chunks **pleins**
    /// de `MIN_CHUNK_SIZE` octets chacun — taille uniforme, ce qui
    /// simplifie les calculs d'offset des tests appelants), pour les tests
    /// qui doivent manipuler individuellement des chunks précis.
    /// `chunk_size = MIN_CHUNK_SIZE` : la plus petite valeur acceptée par
    /// la politique M2 (durcissement), pour que ce fichier passe la
    /// validation structurelle de l'en-tête avant même d'atteindre la
    /// manipulation testée par l'appelant. `total_plaintext_size` est un
    /// multiple exact de `chunk_size` (2 × `MIN_CHUNK_SIZE`), donc le
    /// dernier chunk est lui aussi plein (voir `expected_plaintext_len`).
    /// Chaque appel utilise un sel et un nonce de base fraîchement générés
    /// (aléatoires), donc deux appels produisent toujours des fichiers
    /// avec un `header_hash` différent, même à mot de passe identique.
    fn build_two_chunk_enc(dir: &Path, name: &str) -> (std::path::PathBuf, Password) {
        let password = pwd("mot-de-passe-bas-niveau-test");
        let params = small_params();
        let salt = generate_salt();
        let base_nonce = generate_base_nonce();
        let key = derive_key(&password, &salt, params).unwrap();

        let chunk_size: u32 = MIN_CHUNK_SIZE;
        let plaintext_a = vec![b'A'; chunk_size as usize];
        let plaintext_b = vec![b'B'; chunk_size as usize];
        let total_size = (plaintext_a.len() + plaintext_b.len()) as u64;

        let header = Header {
            salt,
            argon2_params: params,
            base_nonce,
            chunk_size,
            total_chunks: 2,
            total_plaintext_size: total_size,
        };
        let header_bytes = header.to_bytes();
        let header_nonce = derive_nonce(&header.base_nonce, HEADER_NONCE_COUNTER);
        let header_tag =
            encrypt_buffer(&key, Nonce::from_raw_unchecked(header_nonce), &[], &header_bytes)
                .unwrap();

        let mut header_hash_input = Vec::new();
        header_hash_input.extend_from_slice(&header_bytes);
        header_hash_input.extend_from_slice(&header_tag);
        let header_hash: [u8; 32] = Sha256::digest(&header_hash_input).into();

        let aad0 = chunk_aad(&header_hash, 0, false);
        let aad1 = chunk_aad(&header_hash, 1, true);
        let nonce0 = derive_nonce(&header.base_nonce, 0);
        let nonce1 = derive_nonce(&header.base_nonce, 1);
        let c0 = encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce0), &plaintext_a, &aad0).unwrap();
        let c1 = encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce1), &plaintext_b, &aad1).unwrap();

        let enc = dir.join(name);
        let mut f = File::create(&enc).unwrap();
        f.write_all(&header_bytes).unwrap();
        f.write_all(&header_tag).unwrap();
        f.write_all(&c0).unwrap();
        f.write_all(&c1).unwrap();
        drop(f);

        (enc, password)
    }

    #[test]
    fn decrypt_fails_on_duplicated_chunk() {
        let dir = tempdir();
        let (enc, password) = build_two_chunk_enc(&dir, "duplicated.enc");

        // Remplace le second chunk par une copie exacte du premier : même
        // ciphertext+tag, mais son AAD d'origine référence l'index 0, pas 1.
        let chunk_len = MIN_CHUNK_SIZE as usize + TAG_LEN;
        let prefix_len = HEADER_FIXED_LEN + TAG_LEN;
        let mut bytes = fs::read(&enc).unwrap();
        let c0 = bytes[prefix_len..prefix_len + chunk_len].to_vec();
        bytes[prefix_len + chunk_len..prefix_len + 2 * chunk_len].copy_from_slice(&c0);
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("duplicated.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_fails_on_extra_trailing_data() {
        let dir = tempdir();
        let (enc, password) = build_two_chunk_enc(&dir, "trailing.enc");

        let mut bytes = fs::read(&enc).unwrap();
        bytes.push(0x42); // un octet en trop après le dernier chunk attendu
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("trailing.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_fails_on_chunk_from_another_archive() {
        let dir = tempdir();
        let (enc_a, password) = build_two_chunk_enc(&dir, "archive_a.enc");
        let (enc_b, _) = build_two_chunk_enc(&dir, "archive_b.enc");

        // Remplace le premier chunk de l'archive A par le premier chunk de
        // l'archive B (même position, mais `header_hash` différent puisque
        // sel/nonce de base sont propres à chaque archive) : l'AAD ne
        // correspond plus.
        let chunk_len = MIN_CHUNK_SIZE as usize + TAG_LEN;
        let prefix_len = HEADER_FIXED_LEN + TAG_LEN;
        let mut bytes_a = fs::read(&enc_a).unwrap();
        let bytes_b = fs::read(&enc_b).unwrap();
        bytes_a[prefix_len..prefix_len + chunk_len]
            .copy_from_slice(&bytes_b[prefix_len..prefix_len + chunk_len]);
        fs::write(&enc_a, &bytes_a).unwrap();

        let decrypted = dir.join("archive_a.out");
        let result = decrypt_file(&enc_a, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_fails_when_chunk_tag_specifically_modified() {
        let dir = tempdir();
        let (enc, password) = build_two_chunk_enc(&dir, "tag_modified.enc");

        // Altère spécifiquement le dernier octet du TAG du premier chunk
        // (pas le ciphertext), pour couvrir ce cas distinctement du test
        // `decrypt_fails_on_corrupted_chunk` existant (qui altère le
        // ciphertext).
        let chunk_len = MIN_CHUNK_SIZE as usize + TAG_LEN;
        let prefix_len = HEADER_FIXED_LEN + TAG_LEN;
        let mut bytes = fs::read(&enc).unwrap();
        let tag_last_byte_pos = prefix_len + chunk_len - 1;
        bytes[tag_last_byte_pos] ^= 0xFF;
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("tag_modified.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
        assert!(!decrypted.exists());
    }

    // --- M6 : en-tête modifié (chaque champ structurel) ---------------

    #[test]
    fn header_magic_mismatch_is_rejected() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "magic.txt", b"contenu");
        let enc = dir.join("magic.enc");
        let password = pwd("mot-de-passe-magic-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[0] ^= 0xFF; // premier octet du magic
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("magic.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::InvalidHeader)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn header_version_mismatch_is_rejected() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "version.txt", b"contenu");
        let enc = dir.join("version.enc");
        let password = pwd("mot-de-passe-version-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        bytes[4] = 0xFF; // octet de version, juste après le magic (4 octets)
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("version.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::InvalidHeader)));
        assert!(!decrypted.exists());
    }

    // --- M2 (durcissement) : invariants structurels de l'en-tête -------

    #[test]
    fn chunk_size_below_minimum_in_header_is_rejected() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "small_chunk.txt", b"contenu de test");
        let enc = dir.join("small_chunk.enc");
        let password = pwd("mot-de-passe-chunk-min-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        // Offset du champ chunk_size (u32) : 4 (magic) + 1 (version) +
        // 16 (sel) + 9 (params argon2) + 12 (nonce base) = 42.
        let offset = 4 + 1 + 16 + 9 + 12;
        bytes[offset..offset + 4].copy_from_slice(&100u32.to_be_bytes()); // < MIN_CHUNK_SIZE
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("small_chunk.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::InvalidHeader)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn chunk_size_above_maximum_in_header_is_rejected() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "big_chunk.txt", b"contenu de test");
        let enc = dir.join("big_chunk.enc");
        let password = pwd("mot-de-passe-chunk-max-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        let offset = 4 + 1 + 16 + 9 + 12;
        let too_big = crate::format::MAX_CHUNK_SIZE + 1;
        bytes[offset..offset + 4].copy_from_slice(&too_big.to_be_bytes());
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("big_chunk.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::InvalidHeader)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn total_chunks_inconsistent_with_size_is_rejected() {
        let dir = tempdir();
        // Petit fichier -> 1 seul chunk attendu avec DEFAULT_CHUNK_SIZE.
        let input = write_temp_file(&dir, "one_chunk.txt", b"contenu court");
        let enc = dir.join("one_chunk.enc");
        let password = pwd("mot-de-passe-total-chunks-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        // Offset du champ total_chunks (u64) : offset chunk_size (42) + 4.
        let offset = 4 + 1 + 16 + 9 + 12 + 4;
        bytes[offset..offset + 8].copy_from_slice(&2u64.to_be_bytes()); // devrait être 1
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("one_chunk.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::InvalidHeader)));
        assert!(!decrypted.exists());
    }

    // --- M1 (durcissement) : rejet avant authentification du mot de passe

    #[test]
    fn argon2_params_tampered_in_header_rejected_before_password_check() {
        let dir = tempdir();
        let input = write_temp_file(&dir, "argon.txt", b"contenu de test");
        let enc = dir.join("argon.enc");
        let password = pwd("mot-de-passe-argon-tampered-test");
        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut bytes = fs::read(&enc).unwrap();
        // Offset du champ argon2_memory_kib (u32) : 4 (magic) + 1 (version)
        // + 16 (sel) = 21.
        let offset = 4 + 1 + 16;
        let hostile = crate::crypto::MAX_ARGON2_MEMORY_KIB + 1;
        bytes[offset..offset + 4].copy_from_slice(&hostile.to_be_bytes());
        fs::write(&enc, &bytes).unwrap();

        let decrypted = dir.join("argon.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        // Le rejet doit provenir de la politique Argon2 (M1), PAS d'un
        // échec d'authentification du tag — preuve que la vérification a
        // bien lieu avant toute tentative de dérivation/authentification,
        // même avec le bon mot de passe.
        assert!(matches!(
            result,
            Err(FormatError::Crypto(CryptoError::Argon2ParamsOutOfPolicy))
        ));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_fails_on_reordered_chunks() {
        let dir = tempdir();
        // Deux chunks pleins nécessaires : on force un chunk_size minuscule
        // en construisant directement l'en-tête/les chunks à bas niveau
        // plutôt que via encrypt_file (qui utilise DEFAULT_CHUNK_SIZE).
        let password = pwd("mot-de-passe-reordonnancement");
        let params = small_params();
        let salt = generate_salt();
        let base_nonce = generate_base_nonce();
        let key = derive_key(&password, &salt, params).unwrap();

        let chunk_size: u32 = MIN_CHUNK_SIZE;
        let plaintext_a = vec![b'A'; chunk_size as usize];
        let plaintext_b = vec![b'B'; chunk_size as usize];
        let total_size = (plaintext_a.len() + plaintext_b.len()) as u64;

        let header = Header {
            salt,
            argon2_params: params,
            base_nonce,
            chunk_size,
            total_chunks: 2,
            total_plaintext_size: total_size,
        };
        let header_bytes = header.to_bytes();
        let header_nonce = derive_nonce(&header.base_nonce, HEADER_NONCE_COUNTER);
        let header_tag =
            encrypt_buffer(&key, Nonce::from_raw_unchecked(header_nonce), &[], &header_bytes)
                .unwrap();

        let mut header_hash_input = Vec::new();
        header_hash_input.extend_from_slice(&header_bytes);
        header_hash_input.extend_from_slice(&header_tag);
        let header_hash: [u8; 32] = Sha256::digest(&header_hash_input).into();

        // On chiffre le chunk 0 avec l'AAD du chunk 1 et vice-versa : les
        // index sont ainsi incohérents avec leur position réelle dans le
        // flux, ce que l'AAD est censé détecter.
        let aad0 = chunk_aad(&header_hash, 1, false);
        let aad1 = chunk_aad(&header_hash, 0, true);
        let nonce0 = derive_nonce(&header.base_nonce, 0);
        let nonce1 = derive_nonce(&header.base_nonce, 1);
        let c0 = encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce0), &plaintext_a, &aad0).unwrap();
        let c1 = encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce1), &plaintext_b, &aad1).unwrap();

        let enc = dir.join("reordered.enc");
        let mut f = File::create(&enc).unwrap();
        f.write_all(&header_bytes).unwrap();
        f.write_all(&header_tag).unwrap();
        f.write_all(&c0).unwrap();
        f.write_all(&c1).unwrap();
        drop(f);

        let decrypted = dir.join("reordered.out");
        let result = decrypt_file(&enc, &decrypted, &password);
        assert!(matches!(result, Err(FormatError::Corrupted)));
    }

    // --- P0.1 (durcissement, suite à revue externe) : unicité des nonces
    // -------------------------------------------------------------------
    //
    // `derive_nonce` garantit son unicité par construction (XOR d'un
    // `base_nonce` fixe avec un compteur : `f(counter) = base_nonce XOR
    // counter` est injective, donc compteur A != compteur B => nonce A !=
    // nonce B). Les tests ci-dessous rendent cette propriété vérifiable
    // explicitement, plutôt que de reposer uniquement sur ce raisonnement
    // mathématique en commentaire : une régression future de
    // `derive_nonce` (par exemple un XOR partiel, un compteur tronqué, ou
    // un mélange des octets du `base_nonce`) casserait immédiatement l'un
    // de ces tests.

    #[test]
    fn derive_nonce_is_injective_over_a_wide_range_of_counters() {
        use std::collections::HashSet;

        let base_nonce = generate_base_nonce();

        // Échantillon volontairement hétérogène : petits compteurs
        // consécutifs (cas réel le plus fréquent, chunk 0, 1, 2, ...),
        // valeurs autour des limites de u32/u64, et des compteurs
        // "dispersés" pour ne pas se limiter à une progression linéaire.
        let mut counters: Vec<u64> = (0..2_000).collect();
        counters.extend([
            u32::MAX as u64 - 1,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX - 2,
            u64::MAX - 1,
            u64::MAX, // = HEADER_NONCE_COUNTER, inclus volontairement
            0xAAAA_AAAA_AAAA_AAAA,
            0x5555_5555_5555_5555,
        ]);

        // Garde-fou sur l'échantillon lui-même : si deux valeurs de
        // `counters` sont accidentellement identiques (erreur de
        // construction de ce test), l'assertion d'injectivité ci-dessous
        // échouerait pour une raison triviale (même compteur => même
        // nonce, ce qui n'a rien d'anormal) et masquerait une vraie
        // régression. On vérifie donc explicitement l'absence de doublon
        // en entrée avant de tester la propriété qui nous intéresse.
        let distinct_counters: HashSet<u64> = counters.iter().copied().collect();
        assert_eq!(
            distinct_counters.len(),
            counters.len(),
            "l'échantillon de compteurs contient un doublon : ce test doit être corrigé, \
             il ne teste alors plus l'injectivité de derive_nonce"
        );

        let nonces: Vec<[u8; NONCE_LEN]> = counters
            .iter()
            .map(|&c| derive_nonce(&base_nonce, c))
            .collect();

        let unique: HashSet<[u8; NONCE_LEN]> = nonces.iter().copied().collect();

        assert_eq!(
            unique.len(),
            counters.len(),
            "des compteurs distincts ont produit le même nonce pour un même base_nonce : \
             l'invariant d'unicité des nonces (clé fixe => nonce jamais réutilisé) est rompu"
        );
    }

    #[test]
    fn derive_nonce_differing_counters_always_yield_differing_nonces() {
        // Version « par paire » de l'invariant, plus proche de l'énoncé
        // mathématique : pour un base_nonce fixé, compteur A != compteur B
        // => nonce(A) != nonce(B). Vérifiée sur un échantillon de paires
        // couvrant des écarts de compteur très différents (1, grand, ou
        // ne différant que par un seul bit).
        let base_nonce = generate_base_nonce();

        let pairs: &[(u64, u64)] = &[
            (0, 1),
            (0, u64::MAX),
            (1, u64::MAX),
            (1_000, 1_001),
            (0, 1 << 32),
            (1 << 63, (1 << 63) + 1),
            (0xFFFF_FFFF_0000_0000, 0x0000_0000_FFFF_FFFF),
        ];

        for &(a, b) in pairs {
            assert_ne!(a, b, "cas de test invalide : les deux compteurs sont identiques");
            let nonce_a = derive_nonce(&base_nonce, a);
            let nonce_b = derive_nonce(&base_nonce, b);
            assert_ne!(
                nonce_a, nonce_b,
                "compteurs {a} et {b} (distincts) ont produit le même nonce"
            );
        }
    }

    #[test]
    fn header_nonce_never_collides_with_any_chunk_nonce_in_practice() {
        // Sous-cas spécifique et particulièrement sensible de l'invariant
        // ci-dessus : le nonce réservé à l'en-tête (HEADER_NONCE_COUNTER =
        // u64::MAX) ne doit jamais coïncider avec le nonce d'un chunk de
        // données (0..total_chunks-1). Un fichier `.enc` réel ne peut de
        // toute façon pas contenir 2^64 chunks, mais ce test rend cette
        // séparation de domaine explicite plutôt qu'implicite.
        let base_nonce = generate_base_nonce();
        let header_nonce = derive_nonce(&base_nonce, HEADER_NONCE_COUNTER);

        for chunk_index in 0..10_000u64 {
            let chunk_nonce = derive_nonce(&base_nonce, chunk_index);
            assert_ne!(
                header_nonce, chunk_nonce,
                "le nonce de l'en-tête coïncide avec celui du chunk {chunk_index}"
            );
        }
    }

    #[test]
    fn derive_nonce_is_deterministic_for_a_given_base_and_counter() {
        // Propriété complémentaire nécessaire au déchiffrement : le
        // déchiffreur doit pouvoir reconstruire exactement le même nonce
        // que celui utilisé au chiffrement, à partir du seul base_nonce et
        // de l'index attendu (jamais lu depuis le fichier, voir FORMAT.md
        // §6). `derive_nonce` doit donc être une fonction pure.
        let base_nonce = generate_base_nonce();
        for counter in [0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            assert_eq!(
                derive_nonce(&base_nonce, counter),
                derive_nonce(&base_nonce, counter)
            );
        }
    }

    #[test]
    fn progress_is_reported_for_each_chunk_and_reaches_100_percent() {
        let dir = tempdir();
        let mut content = vec![0u8; 2_684_354]; // multi-chunk, comme le test existant
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let input = write_temp_file(&dir, "progress.bin", &content);
        let enc = dir.join("progress.bin.enc");
        let password = pwd("mot-de-passe-progression-test");

        let mut updates: Vec<ProgressUpdate> = Vec::new();
        encrypt_file_with_progress(&input, &enc, &password, small_params(), &mut |u| {
            updates.push(u);
            true
        })
        .unwrap();

        assert_eq!(updates.len(), 3, "3 chunks attendus pour ~2.56 Mo à 1 Mo/chunk");
        assert_eq!(updates.last().unwrap().bytes_done, content.len() as u64);
        assert_eq!(updates.last().unwrap().percent(), 100);
        assert!(updates.windows(2).all(|w| w[0].bytes_done < w[1].bytes_done));
    }

    #[test]
    fn cancelling_mid_progress_leaves_no_output_file() {
        let dir = tempdir();
        let mut content = vec![0u8; 2_684_354];
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let input = write_temp_file(&dir, "cancel.bin", &content);
        let enc = dir.join("cancel.bin.enc");
        let password = pwd("mot-de-passe-annulation-test");

        let mut calls = 0;
        let result = encrypt_file_with_progress(&input, &enc, &password, small_params(), &mut |_| {
            calls += 1;
            calls < 2 // annule après le premier chunk
        });

        assert!(matches!(result, Err(FormatError::Cancelled)));
        assert!(!enc.exists(), "aucun fichier ne doit rester après annulation");
        // Aucun fichier temporaire ne doit non plus traîner (nettoyage RAII
        // via TempPath — voir create_tmp_path). On vérifie que le
        // répertoire est intégralement vide plutôt que de chercher un motif
        // de nom précis, pour rester valable quel que soit le mécanisme de
        // nommage sous-jacent.
        let leftover: Vec<_> = fs::read_dir(&*dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n != "cancel.bin")
            .collect();
        assert!(leftover.is_empty());
    }

    #[test]
    fn encrypt_file_without_progress_still_works_unchanged() {
        // Garantit que le wrapper historique (sans callback de progression)
        // reste inchangé.
        let dir = tempdir();
        let input = write_temp_file(&dir, "unchanged.txt", b"contenu inchange");
        let enc = dir.join("unchanged.txt.enc");
        let decrypted = dir.join("unchanged.txt.out");
        let password = pwd("mot-de-passe-retrocompat");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();
        decrypt_file(&enc, &decrypted, &password).unwrap();
        assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());
    }

    #[test]
    fn decrypt_progress_is_reported_for_each_chunk_and_reaches_100_percent() {
        let dir = tempdir();
        let mut content = vec![0u8; 2_684_354];
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let input = write_temp_file(&dir, "dprogress.bin", &content);
        let enc = dir.join("dprogress.bin.enc");
        let decrypted = dir.join("dprogress.bin.out");
        let password = pwd("mot-de-passe-progression-dechiffrement");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut updates: Vec<ProgressUpdate> = Vec::new();
        decrypt_file_with_progress(&enc, &decrypted, &password, &mut |u| {
            updates.push(u);
            true
        })
        .unwrap();

        assert_eq!(updates.len(), 3);
        assert_eq!(updates.last().unwrap().bytes_done, content.len() as u64);
        assert_eq!(updates.last().unwrap().percent(), 100);
        assert_eq!(fs::read(&decrypted).unwrap(), content);
    }

    #[test]
    fn cancelling_decrypt_mid_progress_leaves_no_output_file() {
        let dir = tempdir();
        let mut content = vec![0u8; 2_684_354];
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let input = write_temp_file(&dir, "dcancel.bin", &content);
        let enc = dir.join("dcancel.bin.enc");
        let decrypted = dir.join("dcancel.bin.out");
        let password = pwd("mot-de-passe-annulation-dechiffrement");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();

        let mut calls = 0;
        let result = decrypt_file_with_progress(&enc, &decrypted, &password, &mut |_| {
            calls += 1;
            calls < 2
        });

        assert!(matches!(result, Err(FormatError::Cancelled)));
        assert!(!decrypted.exists());
    }

    #[test]
    fn decrypt_file_without_progress_still_works_unchanged() {
        // Garantit que le wrapper historique (sans callback de progression)
        // reste inchangé après l'ajout du support de progression.
        let dir = tempdir();
        let input = write_temp_file(&dir, "dunchanged.txt", b"contenu inchange (dechiffrement)");
        let enc = dir.join("dunchanged.txt.enc");
        let decrypted = dir.join("dunchanged.txt.out");
        let password = pwd("mot-de-passe-retrocompat-dechiffrement");

        encrypt_file(&input, &enc, &password, small_params()).unwrap();
        decrypt_file(&enc, &decrypted, &password).unwrap();
        assert_eq!(fs::read(&input).unwrap(), fs::read(&decrypted).unwrap());
    }

    // --- petite aide de test : répertoire temporaire auto-nettoyé ---
    struct TempDir(std::path::PathBuf);
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
            "chiffre_aes_core_test_{}_{}",
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
}
