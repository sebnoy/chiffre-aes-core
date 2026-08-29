//! `chiffre_aes_core` — bibliothèque cœur de l'outil de chiffrement de fichiers.
//!
//! Ce crate ne connaît rien de l'interface utilisateur : il est partagé
//! tel quel entre le CLI, la GUI Slint (desktop) et le pont JNI (Android).
//!
//! # Organisation des modules
//! - [`crypto`] : primitives cryptographiques — dérivation Argon2id,
//!   chiffrement/déchiffrement AES-256-GCM d'un buffer unique, gestion
//!   mémoire (`Zeroizing` / `ZeroizeOnDrop`).
//! - [`format`] : format de fichier `.enc` — en-tête authentifié,
//!   streaming par chunks de 1 Mo, protection contre la
//!   troncature/réordonnancement.
//! - [`compress`] / [`archive`] / [`pipeline`] : compression par fichier,
//!   empaquetage d'arborescences, et assemblage de bout en bout pour
//!   chiffrer/déchiffrer une sélection de fichiers/dossiers.
//! - [`password_policy`] : politique de mot de passe (score `zxcvbn`,
//!   validation bloquante).

pub mod archive;
pub mod compress;
pub mod crypto;
pub mod format;
pub mod password_policy;
pub mod pipeline;

pub use archive::{ArchiveError, ArchiveWarning, ExtractionLimits};
pub use crypto::{
    decrypt_buffer, derive_key, encrypt_buffer, generate_base_nonce, generate_salt,
    Argon2Params, CryptoError, DerivedKey, Password, MAX_ARGON2_ITERATIONS,
    MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
    MIN_ARGON2_PARALLELISM,
};
pub use format::{
    decrypt_file, decrypt_file_with_progress, encrypt_file, encrypt_file_with_progress,
    FormatError, Header, ProgressUpdate, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
pub use password_policy::{
    assess_password, passwords_match, validate_new_password, PasswordAssessment,
    PasswordPolicyError, MIN_LENGTH, REQUIRED_SCORE,
};
pub use pipeline::{
    decrypt_to_dir, decrypt_to_dir_with_progress, encrypt_paths, encrypt_paths_with_progress,
    PipelineError,
};
