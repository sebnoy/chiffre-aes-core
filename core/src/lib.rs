//! `chiffre_aes_core` — bibliothèque cœur de l'outil de chiffrement de fichiers.
//!
//! Ce crate ne connaît rien de l'interface utilisateur : il est partagé
//! tel quel entre le CLI, la GUI Slint (desktop) et le pont JNI (Android).
//!
//! # Deux niveaux d'API
//!
//! - **API container (recommandée pour la quasi-totalité des usages)** —
//!   réexportée directement à la racine de ce crate :
//!   [`encrypt_file`]/[`decrypt_file`] pour un fichier `.enc` unique, ou
//!   [`pipeline::encrypt_paths`]/[`pipeline::decrypt_to_dir`] pour une
//!   sélection de fichiers/dossiers. Ces fonctions gèrent pour vous la
//!   génération et l'unicité des nonces AES-GCM : il n'y a rien à faire
//!   de spécial pour rester dans les clous.
//! - **API cryptographique bas niveau** — [`crypto::encrypt_buffer`] /
//!   [`crypto::decrypt_buffer`], volontairement **non réexportées à la
//!   racine** du crate (accessibles uniquement via `chiffre_aes_core::crypto::`).
//!   Elles prennent un nonce explicite en paramètre : les utiliser
//!   directement transfère à l'appelant la responsabilité de garantir
//!   qu'un même `(clé, nonce)` n'est jamais réutilisé. Voir la
//!   documentation de ces fonctions avant tout usage direct.
//!
//! # Organisation des modules
//! - [`crypto`] : primitives cryptographiques — dérivation Argon2id,
//!   chiffrement/déchiffrement AES-256-GCM d'un buffer unique (API bas
//!   niveau, voir ci-dessus), gestion mémoire (`Zeroizing` /
//!   `ZeroizeOnDrop`).
//! - [`format`] : format de fichier `.enc` — en-tête authentifié,
//!   streaming par chunks de 1 Mo, protection contre la
//!   troncature/réordonnancement.
//! - [`compress`] / [`archive`] / [`pipeline`] : compression par fichier,
//!   empaquetage d'arborescences, et assemblage de bout en bout pour
//!   chiffrer/déchiffrer une sélection de fichiers/dossiers.
//! - [`password_policy`] : politique de mot de passe (score `zxcvbn`,
//!   validation bloquante).

/// Version de `chiffre_aes_core`, telle que déclarée dans son propre
/// `Cargo.toml`. Destinée à être affichée dans l'écran "Informations" des
/// applications qui intègrent ce crate (GUI desktop, Android) : évite de
/// dupliquer/maintenir manuellement ce numéro à un second endroit, qui
/// finirait inévitablement par se désynchroniser de la version réellement
/// liée au binaire.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod archive;
pub mod compress;
pub mod crypto;
pub mod format;
pub mod password_policy;
pub mod pipeline;

pub use archive::{ArchiveError, ArchiveWarning, ExtractionLimits};
// Note : `crypto::encrypt_buffer` et `crypto::decrypt_buffer` sont
// délibérément NON réexportées ici. Ce sont des primitives bas niveau à
// nonce explicite (voir leur documentation dans `crypto.rs`) ; l'API
// recommandée pour chiffrer/déchiffrer est `encrypt_file`/`decrypt_file`
// (ou `pipeline::encrypt_paths`/`decrypt_to_dir`) ci-dessous, qui gèrent
// l'unicité des nonces pour vous. Elles restent accessibles explicitement
// via `chiffre_aes_core::crypto::encrypt_buffer` pour qui en a réellement
// besoin, en connaissance de cause.
pub use crypto::{
    derive_key, generate_base_nonce, generate_salt, Argon2Params, CryptoError, DerivedKey,
    Password, MAX_ARGON2_ITERATIONS, MAX_ARGON2_MEMORY_KIB, MAX_ARGON2_PARALLELISM,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_PARALLELISM,
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
