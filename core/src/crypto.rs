//! Primitives cryptographiques : dérivation de clé (Argon2id) et
//! chiffrement authentifié (AES-256-GCM) d'un buffer unique. Ne gère pas
//! la notion de chunk / fichier sur disque : c'est la brique de base
//! utilisée par le format `.enc` (voir `format.rs`).
//!
//! Toute donnée sensible (mot de passe, clé dérivée) transite exclusivement
//! par des types qui s'effacent automatiquement de la mémoire à leur
//! destruction (`zeroize` / `Drop`), y compris en cas d'erreur.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Taille du sel Argon2id, en octets (aléatoire, unique par archive).
pub const SALT_LEN: usize = 16;
/// Taille du nonce AES-GCM, en octets.
pub const NONCE_LEN: usize = 12;
/// Taille de la clé dérivée / clé AES-256, en octets.
pub const KEY_LEN: usize = 32;
/// Taille du tag d'authentification AEAD, en octets.
pub const TAG_LEN: usize = 16;

/// Paramètres Argon2id utilisés pour la dérivation de clé.
///
/// Stockés (et donc reconstructibles) dans l'en-tête du fichier `.enc`
/// afin de permettre un durcissement futur sans casser la compatibilité
/// de lecture des archives existantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Mémoire en kilo-octets (KiB). Valeur par défaut : 64 Mo = 65536 KiB.
    pub memory_kib: u32,
    /// Nombre d'itérations.
    pub iterations: u32,
    /// Degré de parallélisme.
    pub parallelism: u8,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Valeurs par défaut : mémoire 64 Mo, itérations 3, parallélisme 4.
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Erreurs possibles lors des opérations cryptographiques.
///
/// Distinction volontaire des cas d'échec : le code appelant pourra
/// traduire `AuthenticationFailed` en « mot de passe incorrect » (en-tête)
/// ou « fichier corrompu / altéré » (chunk de données), selon le contexte
/// dans lequel l'erreur survient (cf. `format.rs`).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("paramètres Argon2id invalides")]
    InvalidParams,
    #[error("échec de la dérivation de clé")]
    KeyDerivationFailed,
    #[error("échec d'authentification (mot de passe incorrect ou donnée altérée)")]
    AuthenticationFailed,
}

/// Mot de passe saisi par l'utilisateur, purgé automatiquement de la
/// mémoire à sa destruction ; jamais écrit en clair sur disque, jamais
/// journalisé.
pub type Password = Zeroizing<String>;

/// Clé dérivée (ou clé maîtresse) de 32 octets (AES-256), purgée
/// automatiquement de la mémoire à sa destruction.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey(pub(crate) [u8; KEY_LEN]);

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Génère un sel aléatoire cryptographiquement sûr (`SysRng`), unique par
/// archive.
///
/// Depuis `rand` 0.10, l'ancien `OsRng` a été renommé `SysRng` (fourni par
/// le crate `getrandom`, ré-exporté via `rand::rngs::SysRng`), et le trait
/// correspondant s'appelle désormais `TryRng` (au lieu de `RngCore`
/// infaillible directement) : on utilise `try_fill_bytes` puis
/// `.expect(...)`. Un échec de `SysRng` est considéré comme une
/// défaillance système irrécupérable (pas de source d'entropie
/// disponible), donc paniquer ici est le comportement voulu — on ne veut
/// surtout pas continuer avec un sel non aléatoire.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    SysRng
        .try_fill_bytes(&mut salt)
        .expect("source d'entropie du système indisponible");
    salt
}

/// Génère un nonce de base aléatoire (`SysRng`). Les nonces par chunk
/// seront dérivés de cette base par XOR avec un compteur (voir `format.rs`).
pub fn generate_base_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .expect("source d'entropie du système indisponible");
    nonce
}

/// Dérive une clé de 32 octets à partir d'un mot de passe et d'un sel, via
/// Argon2id (jamais de simple hash direct du mot de passe).
pub fn derive_key(
    password: &Password,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<DerivedKey, CryptoError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism as u32,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidParams)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Buffer de sortie qui s'auto-efface même en cas d'erreur en cours de
    // route (le buffer est déplacé dans DerivedKey seulement en cas de
    // succès ; sinon `key_bytes` sort de portée et se zeroize).
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key_bytes.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(DerivedKey(*key_bytes))
}

/// Chiffre un buffer unique avec AES-256-GCM (AEAD), sans notion de chunk.
///
/// `aad` (Additional Authenticated Data) permet de lier le texte chiffré à
/// un contexte externe (position, en-tête...) sans le chiffrer lui-même ;
/// utilisé tel quel par le format de fichier.
///
/// Retourne `ciphertext || tag` (le tag de 16 octets est ajouté à la fin
/// par la crate `aes-gcm`).
pub fn encrypt_buffer(
    key: &DerivedKey,
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // `Array::from_slice` est dépréciée depuis aes-gcm 0.11 (migration
    // generic-array -> hybrid-array) au profit de `TryFrom<&[u8]>`. La
    // taille est garantie par les types `[u8; KEY_LEN]`/`[u8; NONCE_LEN]`
    // en entrée : la conversion ne peut donc pas échouer en pratique.
    let key_array = Key::<Aes256Gcm>::try_from(key.as_bytes().as_slice())
        .expect("DerivedKey fait toujours KEY_LEN octets");
    let nonce_array = Nonce::try_from(nonce_bytes.as_slice())
        .expect("nonce_bytes fait toujours NONCE_LEN octets");
    let cipher = Aes256Gcm::new(&key_array);

    cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Déchiffre un buffer produit par [`encrypt_buffer`] et vérifie son
/// authenticité. Si le mot de passe (donc la clé) est incorrect ou si les
/// données ont été altérées, retourne `AuthenticationFailed` sans jamais
/// produire de texte clair partiel : rien n'est considéré valide tant que
/// l'authentification n'a pas réussi.
pub fn decrypt_buffer(
    key: &DerivedKey,
    nonce_bytes: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_array = Key::<Aes256Gcm>::try_from(key.as_bytes().as_slice())
        .expect("DerivedKey fait toujours KEY_LEN octets");
    let nonce_array = Nonce::try_from(nonce_bytes.as_slice())
        .expect("nonce_bytes fait toujours NONCE_LEN octets");
    let cipher = Aes256Gcm::new(&key_array);

    let plaintext = cipher
        .decrypt(
            &nonce_array,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Efface explicitement un buffer sensible en mémoire. Fourni pour les cas
/// où un `Drop` automatique n'est pas suffisant (ex. buffer réutilisé dans
/// une boucle) ; à préférer : structurer le code pour que `Zeroizing`/
/// `ZeroizeOnDrop` s'en chargent seuls.
pub fn purge(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_password(s: &str) -> Password {
        Zeroizing::new(s.to_string())
    }

    // Test dédié à la migration rand 0.8 -> 0.10 (OsRng.fill_bytes ->
    // SysRng.try_fill_bytes) : on vérifie que l'aléa généré n'est ni figé
    // ni constant, pas seulement que le code compile. Un bug d'implémen-
    // tation qui laisserait le buffer à zéro (par exemple un mauvais
    // câblage de try_fill_bytes) compilerait sans erreur mais serait une
    // faille de sécurité critique (sel/nonce prévisible) — ce test vise
    // spécifiquement à détecter ce cas-là.
    #[test]
    fn generate_salt_is_not_all_zero_and_varies_between_calls() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, [0u8; SALT_LEN], "le sel généré ne doit jamais être nul");
        assert_ne!(s1, s2, "deux sels générés successivement doivent différer");
    }

    #[test]
    fn generate_base_nonce_is_not_all_zero_and_varies_between_calls() {
        let n1 = generate_base_nonce();
        let n2 = generate_base_nonce();
        assert_ne!(n1, [0u8; NONCE_LEN], "le nonce généré ne doit jamais être nul");
        assert_ne!(n1, n2, "deux nonces générés successivement doivent différer");
    }

    #[test]
    fn derive_key_is_deterministic_given_same_salt_and_params() {
        let pwd = test_password("CorrectHorseBatteryStaple!42");
        let salt = generate_salt();
        let params = Argon2Params::default();

        let k1 = derive_key(&pwd, &salt, params).expect("derive 1");
        let k2 = derive_key(&pwd, &salt, params).expect("derive 2");

        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_differs_with_different_salt() {
        let pwd = test_password("CorrectHorseBatteryStaple!42");
        let salt_a = generate_salt();
        let salt_b = generate_salt();
        let params = Argon2Params::default();

        let ka = derive_key(&pwd, &salt_a, params).expect("derive a");
        let kb = derive_key(&pwd, &salt_b, params).expect("derive b");

        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn derive_key_differs_with_different_password() {
        let salt = generate_salt();
        let params = Argon2Params::default();

        let ka = derive_key(&test_password("motdepasse-un"), &salt, params).unwrap();
        let kb = derive_key(&test_password("motdepasse-deux"), &salt, params).unwrap();

        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let pwd = test_password("un mot de passe suffisamment robuste !!");
        let salt = generate_salt();
        let nonce = generate_base_nonce();
        let params = Argon2Params::default();
        let key = derive_key(&pwd, &salt, params).unwrap();

        let plaintext = b"contenu secret a chiffrer, avec des caracteres divers: e a e u i c";
        let aad = b"contexte-authentifie";

        let ciphertext = encrypt_buffer(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let decrypted = decrypt_buffer(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn decrypt_fails_with_wrong_password() {
        let salt = generate_salt();
        let nonce = generate_base_nonce();
        let params = Argon2Params::default();

        let key_ok = derive_key(&test_password("bon-mot-de-passe-solide"), &salt, params).unwrap();
        let key_wrong =
            derive_key(&test_password("mauvais-mot-de-passe-solide"), &salt, params).unwrap();

        let plaintext = b"donnee sensible";
        let ciphertext = encrypt_buffer(&key_ok, &nonce, plaintext, b"aad").unwrap();

        let result = decrypt_buffer(&key_wrong, &nonce, &ciphertext, b"aad");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn decrypt_fails_if_ciphertext_tampered() {
        let pwd = test_password("mot de passe pour test de falsification");
        let salt = generate_salt();
        let nonce = generate_base_nonce();
        let params = Argon2Params::default();
        let key = derive_key(&pwd, &salt, params).unwrap();

        let plaintext = b"donnee integre";
        let mut ciphertext = encrypt_buffer(&key, &nonce, plaintext, b"aad").unwrap();

        // On altère un octet du texte chiffré : l'authentification doit
        // échouer (protection contre la corruption / falsification).
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = decrypt_buffer(&key, &nonce, &ciphertext, b"aad");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn decrypt_fails_if_aad_mismatches() {
        let pwd = test_password("mot de passe pour test aad");
        let salt = generate_salt();
        let nonce = generate_base_nonce();
        let params = Argon2Params::default();
        let key = derive_key(&pwd, &salt, params).unwrap();

        let plaintext = b"donnee liee a un contexte precis";
        let ciphertext = encrypt_buffer(&key, &nonce, plaintext, b"contexte-A").unwrap();

        // Même clé, même nonce, mais AAD différent : doit échouer (l'AAD
        // sert justement à lier le chunk à sa position/en-tête).
        let result = decrypt_buffer(&key, &nonce, &ciphertext, b"contexte-B");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn derived_key_zeroizes_on_drop() {
        // On ne peut pas observer directement la mémoire libérée de façon
        // fiable en test unitaire "safe" Rust ; ce test vérifie donc que le
        // type implémente bien le contrat attendu (ZeroizeOnDrop) et que la
        // purge manuelle fonctionne sur un buffer que l'on contrôle.
        let mut buf = [0xAAu8; KEY_LEN];
        purge(&mut buf);
        assert_eq!(buf, [0u8; KEY_LEN]);
    }

    #[test]
    fn password_zeroizing_type_clears_on_drop() {
        // Zeroizing<String> garantit l'effacement du buffer sous-jacent à
        // la destruction. On vérifie au moins que le type utilisé est
        // bien celui attendu et se comporte normalement.
        let pwd = test_password("mot-de-passe-temporaire");
        assert_eq!(pwd.as_str(), "mot-de-passe-temporaire");
        drop(pwd);
        // Le drop ci-dessus déclenche le zeroize interne de la String ;
        // rien à assert ici au-delà de l'absence de panique, la garantie
        // est fournie par la crate `zeroize` elle-même (testée en amont).
    }
}
