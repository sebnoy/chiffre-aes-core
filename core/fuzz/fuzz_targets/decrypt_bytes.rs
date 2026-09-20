//! Fuzz `decrypt_bytes` sur un conteneur `.enc` v1 arbitraire, **en mémoire**.
//!
//! Même surface d'attaque que `decrypt_file` (parsing du header v1, tag GCM
//! du header, lecture/déchiffrement de chaque chunk, détection de
//! troncature et de données en trop), atteinte par une autre porte : le
//! conteneur arrive sous forme d'une tranche d'octets, sans fichier ni
//! répertoire temporaire — donc bien plus rapide à fuzzer que `decrypt_file`.
//!
//! Différence importante de corpus : les graines de `decrypt_file` sont les
//! vecteurs indépendants, chiffrés sous *leur* mot de passe ; l'en-tête ne
//! s'authentifie donc jamais avec le mot de passe du harnais et le code de
//! lecture des chunks n'est atteint que par hasard. Ici, les graines de
//! `corpus/decrypt_bytes/` sont **authentifiées avec le mot de passe du
//! harnais** : le fuzzer explore donc réellement la couche « chunks »
//! (AAD, ordre, dernier chunk, troncature) en mutant les octets qui suivent
//! un en-tête valide.
//!
//! Propriétés recherchées, quelle que soit l'entrée :
//! - jamais de panic ;
//! - en cas de succès, le clair n'est jamais plus grand que le conteneur, et
//!   sa capacité n'a jamais dépassé la taille du conteneur (la capacité est
//!   réservée une seule fois, bornée par cette taille : aucune réallocation
//!   qui abandonnerait des copies de clair non effacées).

#![no_main]

use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let password: Zeroizing<String> = Zeroizing::new("mot-de-passe-de-fuzzing".to_string());

    if let Ok(plaintext) = chiffre_aes_core::decrypt_bytes(data, &password) {
        assert!(plaintext.len() <= data.len());
        assert!(plaintext.capacity() <= data.len());
    }
});
