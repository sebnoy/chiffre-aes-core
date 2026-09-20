//! Fuzz de propriété : `decrypt_bytes(encrypt_bytes(x)) == x`, et toute
//! altération d'un seul octet du conteneur est rejetée.
//!
//! Contrairement aux autres cibles (qui fournissent des octets *hostiles* au
//! décodeur), celle-ci fournit des **clairs quelconques** au chemin de
//! chiffrement en mémoire, puis vérifie :
//!
//! 1. l'aller-retour restitue exactement le clair d'origine (y compris le
//!    clair vide) ;
//! 2. modifier **un seul bit** d'un octet quelconque du conteneur produit
//!    (en-tête, tag d'en-tête, chunk, tag de chunk) fait échouer le
//!    déchiffrement — jamais un succès, et surtout jamais un succès avec un
//!    clair différent.
//!
//! Paramètres Argon2id au **minimum autorisé** (8 Mio, 1 itération, 1 lane)
//! pour que la cible reste exploitable : chaque exécution effectue trois
//! dérivations. Elle est donc nettement plus lente que `decrypt_bytes`
//! (de l'ordre de dizaines d'exécutions par seconde) : c'est voulu, la
//! propriété vérifiée est différente.
//!
//! Le `chunk_size` par défaut (1 Mio) impose qu'un fuzzer ne franchit la
//! frontière entre deux chunks qu'avec des entrées de plus de 1 Mio ; pour
//! l'exercer, lancer une campagne avec une longueur maximale élevée :
//! `cargo +nightly fuzz run roundtrip_bytes -- -max_len=3145728`.

#![no_main]

use chiffre_aes_core::Argon2Params;
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let password: Zeroizing<String> = Zeroizing::new("mot-de-passe-de-fuzzing".to_string());
    let params = Argon2Params {
        memory_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };

    let container = chiffre_aes_core::encrypt_bytes(data, &password, params)
        .expect("encrypt_bytes ne doit jamais échouer sur un clair quelconque");

    // 1. Aller-retour exact.
    let decrypted = chiffre_aes_core::decrypt_bytes(&container, &password)
        .expect("un conteneur qu'on vient de produire doit se déchiffrer");
    assert_eq!(&decrypted[..], data);

    // 2. Altération d'un seul bit : position et bit dérivés de l'entrée
    //    (déterministe, donc reproductible à partir du fichier de crash).
    let seed = data
        .iter()
        .fold(data.len(), |acc, b| acc.wrapping_mul(31).wrapping_add(*b as usize));
    let position = seed % container.len();
    let bit = (seed >> 8) % 8;
    let mut tampered = container.clone();
    tampered[position] ^= 1u8 << bit;
    assert!(
        chiffre_aes_core::decrypt_bytes(&tampered, &password).is_err(),
        "altération acceptée : octet {position}, bit {bit}"
    );
});
