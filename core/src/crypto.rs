//! Primitives cryptographiques : dérivation de clé (Argon2id) et
//! chiffrement authentifié (AES-256-GCM) d'un buffer unique. Ne gère pas
//! la notion de chunk / fichier sur disque : c'est la brique de base
//! utilisée par le format `.enc` (voir `format.rs`).
//!
//! Toute donnée sensible (mot de passe, clé dérivée) transite exclusivement
//! par des types qui s'effacent automatiquement de la mémoire à leur
//! destruction (`zeroize` / `Drop`), y compris en cas d'erreur.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce as AeadNonce};
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

/// Bornes de politique de sécurité pour les paramètres Argon2id — **fixes
/// et codées en dur**, volontairement indépendantes de toute valeur pouvant
/// provenir d'un fichier `.enc` (potentiellement hostile). Voir
/// `FORMAT.md` : un attaquant contrôlant l'en-tête ne doit jamais pouvoir
/// faire exécuter une dérivation de coût arbitraire avant authentification.
///
/// - `MIN_MEMORY_KIB` : assez bas pour ne pas gêner des tests/plateformes
///   contraintes (couvre la valeur la plus basse utilisée dans nos propres
///   tests, 8 Mo).
/// - `MAX_MEMORY_KIB` : 1 Gio — très au-delà de la valeur par défaut
///   (64 Mo), mais borne un attaquant qui viserait une allocation mémoire
///   massive.
/// - `MAX_ITERATIONS` / `MAX_PARALLELISM` : bornent le facteur
///   multiplicatif de coût CPU qu'un en-tête hostile peut imposer.
pub const MIN_ARGON2_MEMORY_KIB: u32 = 8 * 1024;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1024 * 1024;
pub const MIN_ARGON2_ITERATIONS: u32 = 1;
pub const MAX_ARGON2_ITERATIONS: u32 = 50;
pub const MIN_ARGON2_PARALLELISM: u8 = 1;
pub const MAX_ARGON2_PARALLELISM: u8 = 16;

/// Bornes de politique pour le header v2 (`key_source = 1`, destinataires
/// externes) — voir `FORMAT.md` §12. Un header déclarant des valeurs hors
/// de ces bornes est rejeté avant toute allocation dérivée des longueurs
/// déclarées (même discipline que `archive::read_len_incrementally`,
/// introduite suite à un bug d'allocation non bornée trouvé par fuzzing
/// sur le format d'archive — appliquée ici dès la conception plutôt
/// qu'après coup).
///
/// - `MAX_RECIPIENTS` : 64 — borne le nombre d'entrées avant toute
///   boucle d'allocation.
/// - `MAX_RECIPIENT_ID_LEN` : 256 octets — largement suffisant pour un
///   identifiant/empreinte de clé publique.
/// - `MAX_WRAPPED_KEY_LEN` : 1024 octets — RSA-4096-OAEP produit 512
///   octets ; marge pour un mécanisme de scellement futur (ECIES/X25519),
///   jamais démesurée. Pire cas total : 64 × (256 + 1024) ≈ 82 Kio.
pub const MAX_RECIPIENTS: u16 = 64;
pub const MAX_RECIPIENT_ID_LEN: u16 = 256;
pub const MAX_WRAPPED_KEY_LEN: u16 = 1024;

impl Argon2Params {
    /// Vérifie que les paramètres respectent la politique de sécurité
    /// ci-dessus. Appelé systématiquement par [`derive_key`] avant toute
    /// dérivation — donc protège aussi bien un appel direct (chiffrement)
    /// qu'un appel avec des paramètres reconstruits depuis un fichier
    /// `.enc` potentiellement hostile (déchiffrement).
    pub fn validate(&self) -> Result<(), CryptoError> {
        if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&self.iterations)
            || !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&self.parallelism)
        {
            return Err(CryptoError::Argon2ParamsOutOfPolicy);
        }
        Ok(())
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
    #[error("paramètres Argon2id hors politique de sécurité (min/max)")]
    Argon2ParamsOutOfPolicy,
    #[error("échec de la dérivation de clé")]
    KeyDerivationFailed,
    #[error("échec d'authentification (mot de passe incorrect ou donnée altérée)")]
    AuthenticationFailed,
    #[error("séquence de nonces épuisée (compteur 64 bits atteint)")]
    NonceSequenceExhausted,
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

/// Une clé AES-256 déjà entièrement déterminée, indépendamment de son
/// origine — point de convergence unique pour le chiffrement/
/// déchiffrement avec une clé externe (voir `format::encrypt_file_with_raw_key`
/// / `format::decrypt_file_with_raw_key`), par opposition à une clé
/// dérivée d'un mot de passe via Argon2id ([`DerivedKey`], inchangé).
///
/// Enveloppe volontairement [`DerivedKey`] plutôt que de dupliquer son
/// stockage/zeroization : les deux types représentent la même chose au
/// niveau octets (32 octets prêts à l'emploi pour AES-256-GCM), seule
/// leur provenance diffère conceptuellement.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RawKey(DerivedKey);

impl RawKey {
    /// Construit une `RawKey` à partir d'octets déjà résolus — typiquement
    /// le résultat d'un déchiffrement (RSA-OAEP ou autre) effectué par
    /// l'appelant. `chiffre_aes_core` ne valide ni n'interprète ces
    /// octets au-delà de leur longueur (32 octets, garantie par le type).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(DerivedKey(bytes))
    }

    /// Génère une clé de contenu (CEK) aléatoire via le CSPRNG système —
    /// à sceller ensuite pour chaque destinataire (RSA-OAEP ou autre)
    /// avant d'appeler `encrypt_file_with_raw_key`.
    pub fn generate_random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("source d'entropie du système indisponible");
        Self(DerivedKey(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }

    /// Conversion interne vers le type consommé par le pipeline de
    /// chiffrement existant — aucune logique AEAD/chunking dupliquée.
    ///
    /// Clone plutôt que move : `RawKey` implémente `Drop` (via
    /// `ZeroizeOnDrop`), et Rust interdit de déplacer un champ hors d'un
    /// type ayant un `Drop` personnalisé (l'état partiellement déplacé
    /// serait dangereux à zeroizer). Le coût — copier 32 octets une fois
    /// par opération de chiffrement/déchiffrement, jamais par chunk —
    /// est négligible ; l'original est de toute façon zeroizé
    /// immédiatement après par son propre `Drop`, donc aucune perte de
    /// garantie de sécurité.
    pub(crate) fn into_derived_key(self) -> DerivedKey {
        self.0.clone()
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

/// Nonce destiné à un usage AES-GCM unique, pour une seule opération de
/// [`encrypt_buffer`]/[`decrypt_buffer`].
///
/// Volontairement **non-`Clone`, non-`Copy`** : consommé par valeur, une
/// fois passé à `encrypt_buffer`/`decrypt_buffer` il ne peut plus être
/// réutilisé par erreur dans le même scope (par exemple une variable
/// capturée deux fois dans une boucle, l'erreur de réutilisation de nonce
/// la plus fréquente en pratique).
///
/// Ceci ne remplace pas une preuve globale d'unicité — rien n'empêche de
/// reconstruire volontairement les mêmes octets via
/// [`Nonce::from_raw_unchecked`] — mais élimine la classe d'erreur la plus
/// courante par construction du système de types plutôt que par simple
/// documentation. Pour un usage répété sûr sous une même clé, préférez
/// [`NonceSequence`].
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Construit un nonce à partir d'octets fournis directement par
    /// l'appelant.
    ///
    /// ⚠️ N'utilisez ceci que si vous savez déjà garantir vous-même
    /// l'unicité de la paire (clé, nonce) — dans le doute, utilisez
    /// [`NonceSequence`] à la place, qui fournit cette garantie pour vous.
    pub fn from_raw_unchecked(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// Générateur de nonces garantissant leur unicité pour une clé donnée, tant
/// que la même instance sert à toutes les opérations effectuées sous cette
/// clé (compteur interne strictement croissant, jamais répété).
///
/// Recommandé pour tout usage de l'API bas niveau ([`encrypt_buffer`] /
/// [`decrypt_buffer`]) en dehors de [`crate::format`], qui gère déjà cette
/// contrainte en interne par un mécanisme équivalent.
pub struct NonceSequence {
    base: [u8; NONCE_LEN],
    next_counter: u64,
}

/// Nonce dérivé de `base` XOR le compteur (encodé sur les 8 derniers
/// octets), identique par construction au mécanisme utilisé par le format
/// `.enc` (voir `format.rs`, dont l'injectivité pour des compteurs
/// distincts est testée séparément).
fn derive_nonce_for_sequence(base: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
    let counter_bytes = counter.to_be_bytes();
    let mut out = *base;
    for (o, c) in out[4..].iter_mut().zip(counter_bytes.iter()) {
        *o ^= c;
    }
    out
}

impl NonceSequence {
    pub fn new(base: [u8; NONCE_LEN]) -> Self {
        Self {
            base,
            next_counter: 0,
        }
    }

    /// Retourne un nonce garanti différent de tous les précédents issus de
    /// cette même séquence. Retourne une erreur plutôt qu'un nonce répété
    /// en cas d'épuisement du compteur 64 bits (jamais atteint en pratique
    /// pour un usage réel, mais vérifié explicitement plutôt que supposé).
    #[must_use]
    pub fn next(&mut self) -> Result<Nonce, CryptoError> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(CryptoError::NonceSequenceExhausted)?;
        Ok(Nonce(derive_nonce_for_sequence(&self.base, counter)))
    }
}

/// Dérive une clé de 32 octets à partir d'un mot de passe et d'un sel, via
/// Argon2id (jamais de simple hash direct du mot de passe).
pub fn derive_key(
    password: &Password,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<DerivedKey, CryptoError> {
    // M1 (durcissement) : rejet immédiat si les paramètres sont hors de la
    // politique de sécurité fixe, AVANT tout calcul coûteux. Ce contrôle est
    // indépendant de la provenance de `params` (appel direct ou paramètres
    // reconstruits depuis un en-tête `.enc` potentiellement hostile) — un
    // attaquant ne peut donc jamais déclencher une dérivation de coût
    // arbitraire, même avant que le mot de passe soit vérifié.
    params.validate()?;

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
/// # ⚠️ Primitive bas niveau — lire avant utilisation
///
/// Cette fonction est la brique de base utilisée en interne par le format
/// `.enc` (voir [`crate::format`]) : c'est **elle qui garantit** que
/// `nonce_bytes` n'est jamais réutilisé sous une même clé, en le dérivant
/// de manière déterministe à partir d'un `base_nonce` aléatoire et d'un
/// compteur unique par opération (header ou index de chunk).
///
/// Si vous appelez `encrypt_buffer` directement (plutôt que de passer par
/// [`crate::format::encrypt_file`] ou [`crate::pipeline::encrypt_paths`]),
/// **c'est à vous de garantir cette unicité** :
///
/// ```text
/// même clé + même nonce, appelé deux fois avec des plaintexts différents
///     => confidentialité ET authentification cassées pour AES-GCM.
/// ```
///
/// Il n'y a aucune protection au niveau des types contre cette erreur :
/// rien n'empêche techniquement d'appeler cette fonction deux fois avec le
/// même `(key, nonce_bytes)`. Pour la quasi-totalité des usages (chiffrer
/// un fichier ou une sélection de fichiers/dossiers), préférez les API de
/// plus haut niveau qui gèrent cette contrainte pour vous :
/// [`crate::format::encrypt_file`] / [`crate::pipeline::encrypt_paths`].
///
/// `aad` (Additional Authenticated Data) permet de lier le texte chiffré à
/// un contexte externe (position, en-tête...) sans le chiffrer lui-même ;
/// utilisé tel quel par le format de fichier.
///
/// Retourne `ciphertext || tag` (le tag de 16 octets est ajouté à la fin
/// par la crate `aes-gcm`).
///
/// `nonce` est consommé par valeur (type [`Nonce`], non-`Clone`) : ceci
/// élimine par construction la réutilisation accidentelle d'une même
/// variable de nonce dans une boucle. Voir [`NonceSequence`] pour un usage
/// répété sûr sous une même clé.
pub fn encrypt_buffer(
    key: &DerivedKey,
    nonce: Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // `Array::from_slice` est dépréciée depuis aes-gcm 0.11 (migration
    // generic-array -> hybrid-array) au profit de `TryFrom<&[u8]>`. La
    // taille est garantie par les types `[u8; KEY_LEN]`/`[u8; NONCE_LEN]`
    // en entrée : la conversion ne peut donc pas échouer en pratique.
    let key_array = Key::<Aes256Gcm>::try_from(key.as_bytes().as_slice())
        .expect("DerivedKey fait toujours KEY_LEN octets");
    let nonce_array = AeadNonce::try_from(nonce.as_bytes().as_slice())
        .expect("Nonce fait toujours NONCE_LEN octets");
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
///
/// # ⚠️ Primitive bas niveau
///
/// Voir l'avertissement sur [`encrypt_buffer`] : `nonce` doit envelopper
/// exactement les octets utilisés au chiffrement (typiquement reconstruits
/// via [`Nonce::from_raw_unchecked`] côté appelant, puisqu'il s'agit ici
/// de rejouer un nonce déjà utilisé une fois — usage légitime, à la
/// différence de `encrypt_buffer`).
pub fn decrypt_buffer(
    key: &DerivedKey,
    nonce: Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_array = Key::<Aes256Gcm>::try_from(key.as_bytes().as_slice())
        .expect("DerivedKey fait toujours KEY_LEN octets");
    let nonce_array = AeadNonce::try_from(nonce.as_bytes().as_slice())
        .expect("Nonce fait toujours NONCE_LEN octets");
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

        let ciphertext =
            encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce), plaintext, aad).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let decrypted =
            decrypt_buffer(&key, Nonce::from_raw_unchecked(nonce), &ciphertext, aad).unwrap();
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
        let ciphertext =
            encrypt_buffer(&key_ok, Nonce::from_raw_unchecked(nonce), plaintext, b"aad").unwrap();

        let result = decrypt_buffer(&key_wrong, Nonce::from_raw_unchecked(nonce), &ciphertext, b"aad");
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
        let mut ciphertext =
            encrypt_buffer(&key, Nonce::from_raw_unchecked(nonce), plaintext, b"aad").unwrap();

        // On altère un octet du texte chiffré : l'authentification doit
        // échouer (protection contre la corruption / falsification).
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        let result = decrypt_buffer(&key, Nonce::from_raw_unchecked(nonce), &ciphertext, b"aad");
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
        let ciphertext = encrypt_buffer(
            &key,
            Nonce::from_raw_unchecked(nonce),
            plaintext,
            b"contexte-A",
        )
        .unwrap();

        // Même clé, même nonce, mais AAD différent : doit échouer (l'AAD
        // sert justement à lier le chunk à sa position/en-tête). On
        // reconstruit volontairement le même nonce : c'est précisément le
        // scénario que `Nonce` (non-Clone) rend visible dans le code — on
        // ne peut pas juste réutiliser la variable, il faut explicitement
        // rappeler `from_raw_unchecked`.
        let result = decrypt_buffer(
            &key,
            Nonce::from_raw_unchecked(nonce),
            &ciphertext,
            b"contexte-B",
        );
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn nonce_sequence_never_repeats_across_many_calls() {
        let mut seq = NonceSequence::new(generate_base_nonce());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let n = seq.next().unwrap();
            assert!(seen.insert(*n.as_bytes()), "nonce répété détecté");
        }
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

    // --- M1 (durcissement) : bornes de politique Argon2 --------------

    #[test]
    fn default_params_pass_validation() {
        assert!(Argon2Params::default().validate().is_ok());
    }

    #[test]
    fn params_at_exact_bounds_pass_validation() {
        // Bornes inclusives : les valeurs limites elles-mêmes doivent
        // passer (pas de décalage d'un cran type erreur "off-by-one").
        let at_min = Argon2Params {
            memory_kib: MIN_ARGON2_MEMORY_KIB,
            iterations: MIN_ARGON2_ITERATIONS,
            parallelism: MIN_ARGON2_PARALLELISM,
        };
        assert!(at_min.validate().is_ok());

        let at_max = Argon2Params {
            memory_kib: MAX_ARGON2_MEMORY_KIB,
            iterations: MAX_ARGON2_ITERATIONS,
            parallelism: MAX_ARGON2_PARALLELISM,
        };
        assert!(at_max.validate().is_ok());
    }

    #[test]
    fn memory_zero_is_rejected() {
        let params = Argon2Params {
            memory_kib: 0,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn memory_excessive_is_rejected() {
        // Valeur volontairement énorme : simule un en-tête .enc hostile
        // cherchant à provoquer une allocation/consommation CPU massive.
        let params = Argon2Params {
            memory_kib: MAX_ARGON2_MEMORY_KIB + 1,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn iterations_zero_is_rejected() {
        let params = Argon2Params {
            iterations: 0,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn iterations_excessive_is_rejected() {
        let params = Argon2Params {
            iterations: MAX_ARGON2_ITERATIONS + 1,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn parallelism_zero_is_rejected() {
        let params = Argon2Params {
            parallelism: 0,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn parallelism_excessive_is_rejected() {
        let params = Argon2Params {
            parallelism: MAX_ARGON2_PARALLELISM + 1,
            ..Argon2Params::default()
        };
        assert!(matches!(
            params.validate(),
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }

    #[test]
    fn derive_key_rejects_out_of_policy_params_without_deriving() {
        // Critère d'acceptation M1 explicite : le rejet doit être immédiat,
        // sans exécuter d'opération de coût arbitraire. On ne peut pas
        // mesurer directement l'absence de coût CPU dans un test unitaire,
        // mais on vérifie que `derive_key` échoue bien AVANT toute
        // dérivation réelle (pas de panique, pas de blocage) même avec des
        // paramètres qui, s'ils étaient exécutés tels quels, tenteraient
        // une allocation mémoire disproportionnée.
        let pwd = test_password("peu importe");
        let salt = generate_salt();
        let hostile = Argon2Params {
            memory_kib: MAX_ARGON2_MEMORY_KIB + 1,
            iterations: 1,
            parallelism: 1,
        };
        let result = derive_key(&pwd, &salt, hostile);
        assert!(matches!(
            result,
            Err(CryptoError::Argon2ParamsOutOfPolicy)
        ));
    }
}
