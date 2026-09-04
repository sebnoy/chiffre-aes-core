#!/usr/bin/env python3
"""
Générateur INDÉPENDANT (Python) de vecteurs de test pour le format .enc
de chiffre_aes_core, à partir de la seule spécification FORMAT.md.

N'importe et ne dépend d'AUCUN code du crate Rust. Dépendances :
argon2-cffi, cryptography (deux bibliothèques indépendantes de
RustCrypto, chacune largement utilisée et testée séparément).

Corrige un bug introduit dans une révision précédente de ce script : une
boucle `for name in ["001","002","003"]` réécrivait les TROIS fichiers de
sortie avec le contenu du SEUL appel en cours à chaque invocation de
`generate_vector()` — après `main()`, les trois `vector_00N.json/.enc`
se retrouvaient tous avec le contenu du dernier appel (vector_003, le cas
fichier vide) au lieu de leur contenu respectif. Chaque appel écrit
maintenant uniquement son propre fichier, sous son propre nom.

Étend également le générateur au header v2 (`FORMAT_VERSION_V2 = 2`,
destinataires externes) — voir `generate_vector_v2_external()` — pour
fournir un vecteur indépendant ET une entrée de corpus de fuzzing valide
pour `HeaderV2::from_reader`, qu'aucun vecteur v1 ne peut exercer (un
fichier v1 est rejeté par construction avant même d'atteindre le code de
parsing v2).
"""
import argon2.low_level as a2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import json
import math
import os

HEADER_NONCE_COUNTER = 0xFFFFFFFFFFFFFFFF  # u64::MAX
MAGIC = b"ENC1"

# Chemins résolus par rapport à l'emplacement du script lui-même, PAS au
# répertoire courant d'où il est lancé — contrairement à la version
# précédente (`os.path.join("..", "tests", "vectors")`), qui ne
# fonctionnait que si le script était invoqué depuis `core/scripts/`
# exactement. Robuste quel que soit le répertoire d'appel.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "tests", "vectors"))
FUZZ_CORPUS_DIR = os.path.normpath(
    os.path.join(SCRIPT_DIR, "..", "fuzz", "corpus", "decrypt_file_with_raw_key")
)


def derive_nonce(base_nonce: bytes, counter: int) -> bytes:
    """base_nonce XOR (0..0 || counter_be) sur les 8 derniers octets."""
    counter_bytes = counter.to_bytes(8, "big")
    out = bytearray(base_nonce)
    for i in range(8):
        out[4 + i] ^= counter_bytes[i]
    return bytes(out)


def build_chunks(key: bytes, base_nonce: bytes, header_bytes: bytes, header_tag: bytes,
                  chunk_size: int, total_chunks: int, total_plaintext_size: int,
                  plaintext: bytes):
    """Boucle de chunking partagée entre les générateurs v1 et v2 — le
    découpage AAD/nonce par chunk est strictement identique dans les deux
    versions du format, seule la construction de l'en-tête diffère."""
    header_hash = hashlib.sha256(header_bytes + header_tag).digest()
    aesgcm = AESGCM(key)

    chunks = []
    enc_file = bytearray(header_bytes + header_tag)
    offset = 0
    for index in range(total_chunks):
        is_last = index == total_chunks - 1
        if is_last:
            chunk_plaintext = plaintext[offset:]
        else:
            chunk_plaintext = plaintext[offset:offset + chunk_size]
        offset += len(chunk_plaintext)

        aad = header_hash + index.to_bytes(8, "big") + (b"\x01" if is_last else b"\x00")
        nonce = derive_nonce(base_nonce, index)
        ciphertext = aesgcm.encrypt(nonce, chunk_plaintext, aad)

        chunks.append({
            "index": index,
            "is_last": is_last,
            "plaintext_len": len(chunk_plaintext),
            "aad_hex": aad.hex(),
            "nonce_hex": nonce.hex(),
            "ciphertext_with_tag_hex": ciphertext.hex(),
        })
        enc_file.extend(ciphertext)

    assert offset == total_plaintext_size, "tous les octets du plaintext doivent avoir ete consommes"
    return chunks, bytes(enc_file), header_hash


def write_vector(name: str, vector: dict, enc_file: bytes, also_seed_fuzz_corpus: bool = False):
    os.makedirs(VECTORS_DIR, exist_ok=True)
    json_path = os.path.join(VECTORS_DIR, f"vector_{name}.json")
    enc_path = os.path.join(VECTORS_DIR, f"vector_{name}.enc")

    with open(json_path, "w") as f:
        json.dump(vector, f, indent=2)
    with open(enc_path, "wb") as f:
        f.write(enc_file)

    if also_seed_fuzz_corpus:
        os.makedirs(FUZZ_CORPUS_DIR, exist_ok=True)
        seed_path = os.path.join(FUZZ_CORPUS_DIR, f"seed_vector_{name}.enc")
        with open(seed_path, "wb") as f:
            f.write(enc_file)
        print(f"  -> corpus de fuzzing ensemence : {seed_path}")

    print(f"vector_{name} ecrit : {json_path}")


# ============================================================================
# Header v1 : mot de passe (Argon2id), FORMAT_VERSION = 1 — inchange.
# ============================================================================

def build_header_v1(salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
                     base_nonce, chunk_size, total_chunks, total_plaintext_size):
    h = MAGIC
    h += (1).to_bytes(1, "big")
    h += salt
    h += argon2_memory_kib.to_bytes(4, "big")
    h += argon2_iterations.to_bytes(4, "big")
    h += argon2_parallelism.to_bytes(1, "big")
    h += base_nonce
    h += chunk_size.to_bytes(4, "big")
    h += total_chunks.to_bytes(8, "big")
    h += total_plaintext_size.to_bytes(8, "big")
    assert len(h) == 62, f"header v1 doit faire 62 octets, obtenu {len(h)}"
    return h


def generate_vector(name: str, password: bytes, salt: bytes, base_nonce: bytes,
                     argon2_memory_kib: int, argon2_iterations: int,
                     argon2_parallelism: int, chunk_size: int, plaintext: bytes,
                     description: str):
    assert len(salt) == 16, f"salt doit faire 16 octets, obtenu {len(salt)}"
    assert len(base_nonce) == 12, f"base_nonce doit faire 12 octets, obtenu {len(base_nonce)}"

    key = a2.hash_secret_raw(
        secret=password, salt=salt, time_cost=argon2_iterations,
        memory_cost=argon2_memory_kib, parallelism=argon2_parallelism,
        hash_len=32, type=a2.Type.ID, version=19,  # 0x13 == argon2::Version::V0x13
    )

    total_plaintext_size = len(plaintext)
    total_chunks = 1 if total_plaintext_size == 0 else math.ceil(total_plaintext_size / chunk_size)

    header = build_header_v1(salt, argon2_memory_kib, argon2_iterations,
                              argon2_parallelism, base_nonce, chunk_size,
                              total_chunks, total_plaintext_size)

    header_nonce = derive_nonce(base_nonce, HEADER_NONCE_COUNTER)
    header_tag = AESGCM(key).encrypt(header_nonce, b"", header)
    assert len(header_tag) == 16

    chunks, enc_file, header_hash = build_chunks(
        key, base_nonce, header, header_tag, chunk_size, total_chunks,
        total_plaintext_size, plaintext,
    )

    vector = {
        "description": description,
        "format_version": 1,
        "inputs": {
            "password_utf8": password.decode(),
            "salt_hex": salt.hex(),
            "base_nonce_hex": base_nonce.hex(),
            "argon2_memory_kib": argon2_memory_kib,
            "argon2_iterations": argon2_iterations,
            "argon2_parallelism": argon2_parallelism,
            "chunk_size": chunk_size,
            "plaintext_utf8": plaintext.decode(),
        },
        "expected": {
            "derived_key_hex": key.hex(),
            "header_hex": header.hex(),
            "header_tag_hex": header_tag.hex(),
            "header_hash_hex": header_hash.hex(),
            "total_chunks": total_chunks,
            "chunks": chunks,
            "full_enc_file_hex": enc_file.hex(),
        },
    }

    write_vector(name, vector, enc_file)


# ============================================================================
# Header v2 : destinataires externes, FORMAT_VERSION_V2 = 2 — nouveau.
# La clé de contenu (CEK) est fournie directement, jamais dérivée d'un
# mot de passe : c'est tout le principe du key_source=1 (voir FORMAT.md §12
# et core/src/format.rs, HeaderV2::from_reader).
# ============================================================================

def build_header_v2_external(recipients, base_nonce, chunk_size, total_chunks,
                              total_plaintext_size):
    """`recipients` : liste de (recipient_id: bytes, wrapped_key: bytes)."""
    h = MAGIC
    h += (2).to_bytes(1, "big")   # FORMAT_VERSION_V2
    h += (1).to_bytes(1, "big")   # key_source = 1 (destinataires externes)
    h += len(recipients).to_bytes(2, "big")
    for recipient_id, wrapped_key in recipients:
        h += len(recipient_id).to_bytes(2, "big")
        h += recipient_id
        h += len(wrapped_key).to_bytes(2, "big")
        h += wrapped_key
    h += base_nonce
    h += chunk_size.to_bytes(4, "big")
    h += total_chunks.to_bytes(8, "big")
    h += total_plaintext_size.to_bytes(8, "big")
    return h


def generate_vector_v2_external(name: str, cek: bytes, recipients, base_nonce: bytes,
                                 chunk_size: int, plaintext: bytes, description: str,
                                 also_seed_fuzz_corpus: bool = True):
    """
    `cek` : clé de contenu de 32 octets, fournie directement (simule ce
    qu'un futur crate RSA obtiendrait après descellement RSA-OAEP — ce
    script ne fait jamais lui-même de RSA, il traite `wrapped_key` comme
    un blob opaque exactement comme le fait chiffre_aes_core).
    `recipients` : liste de (recipient_id: bytes, wrapped_key: bytes).
    """
    assert len(cek) == 32, f"cek doit faire 32 octets, obtenu {len(cek)}"
    assert len(base_nonce) == 12

    total_plaintext_size = len(plaintext)
    total_chunks = 1 if total_plaintext_size == 0 else math.ceil(total_plaintext_size / chunk_size)

    header = build_header_v2_external(recipients, base_nonce, chunk_size,
                                       total_chunks, total_plaintext_size)

    header_nonce = derive_nonce(base_nonce, HEADER_NONCE_COUNTER)
    header_tag = AESGCM(cek).encrypt(header_nonce, b"", header)
    assert len(header_tag) == 16

    chunks, enc_file, header_hash = build_chunks(
        cek, base_nonce, header, header_tag, chunk_size, total_chunks,
        total_plaintext_size, plaintext,
    )

    vector = {
        "description": description,
        "format_version": 2,
        "inputs": {
            "cek_hex": cek.hex(),
            "recipients": [
                {"recipient_id_hex": rid.hex(), "wrapped_key_hex": wk.hex()}
                for rid, wk in recipients
            ],
            "base_nonce_hex": base_nonce.hex(),
            "chunk_size": chunk_size,
            "plaintext_utf8": plaintext.decode(),
        },
        "expected": {
            "header_hex": header.hex(),
            "header_tag_hex": header_tag.hex(),
            "header_hash_hex": header_hash.hex(),
            "total_chunks": total_chunks,
            "chunks": chunks,
            "full_enc_file_hex": enc_file.hex(),
        },
    }

    write_vector(name, vector, enc_file, also_seed_fuzz_corpus=also_seed_fuzz_corpus)


def main():
    # --- vector_001 : v1, un seul chunk -----------------------------------
    generate_vector(
        name="001",
        password=b"mot-de-passe-vecteur-test-independant-01",
        salt=bytes.fromhex("00112233445566778899aabbccddeeff"),
        base_nonce=bytes.fromhex("0102030405060708090a0b0c"),
        argon2_memory_kib=8 * 1024, argon2_iterations=1, argon2_parallelism=1,
        chunk_size=1024 * 1024,
        plaintext=b"Ceci est un vecteur de test independant pour chiffre-aes-core.\n",
        description="Cas nominal v1, un seul chunk.",
    )

    # --- vector_002 : v1, plusieurs chunks, dernier partiel ---------------
    # chunk_size doit respecter MIN_CHUNK_SIZE (1024 octets, core/src/format.rs) :
    # la version précédente de ce vecteur utilisait chunk_size=16, rejeté par
    # `decrypt_file` avant même l'authentification (`InvalidHeader`) car sous
    # cette borne de politique — incohérence entre ce générateur et le code
    # Rust, jamais alignés jusqu'ici. Texte construit dynamiquement pour
    # forcer 3 chunks (2 pleins + 1 partiel) avec cette taille réaliste.
    v2_base_sentence = (
        b"Vecteur multi-chunks avec chunk_size=MIN_CHUNK_SIZE (1024 octets) : "
        b"chaque chunk authentifie son index et sa position finale dans le flux. "
    )
    v1_002_total_len = 1024 * 2 + 500  # 3 chunks : 1024, 1024, 500 (dernier partiel)
    v1_002_plaintext = (v2_base_sentence * (v1_002_total_len // len(v2_base_sentence) + 2))[:v1_002_total_len]

    generate_vector(
        name="002",
        password=b"mot-de-passe-vecteur-test-independant-02",
        salt=bytes.fromhex("112233445566778899aabbccddeeff00"),
        base_nonce=bytes.fromhex("aabbccddeeff001122334455"),
        argon2_memory_kib=8 * 1024, argon2_iterations=1, argon2_parallelism=1,
        chunk_size=1024,
        plaintext=v1_002_plaintext,
        description="v1, plusieurs chunks (3), chunk_size=MIN_CHUNK_SIZE, dernier chunk partiel (500 octets).",
    )

    # --- vector_003 : v1, fichier vide -------------------------------------
    generate_vector(
        name="003",
        password=b"mot-de-passe-vecteur-test-independant-03",
        salt=bytes.fromhex("ffeeddccbbaa00112233445566778899"[:32]),
        base_nonce=bytes.fromhex("000000000000000000000001"),
        argon2_memory_kib=8 * 1024, argon2_iterations=1, argon2_parallelism=1,
        chunk_size=1024,
        plaintext=b"",
        description="v1, fichier vide : 1 chunk vide explicitement marque dernier.",
    )

    # --- vector_v2_001 : v2, un seul destinataire --------------------------
    generate_vector_v2_external(
        name="v2_001",
        cek=bytes.fromhex("00" * 31 + "01"),  # cle de contenu fixe, arbitraire
        recipients=[(b"recipient-solo", b"wrapped-key-blob-opaque-solo-000001")],
        base_nonce=bytes.fromhex("101112131415161718191a1b"),
        chunk_size=1024 * 1024,
        plaintext=b"Vecteur v2 (destinataire externe) independant pour chiffre-aes-core.\n",
        description="v2, key_source=1, un seul destinataire, un seul chunk.",
    )

    # --- vector_v2_002 : v2, plusieurs destinataires, plusieurs chunks -----
    # Même correctif que vector_002 (v1) : chunk_size doit respecter
    # MIN_CHUNK_SIZE (1024 octets) — HeaderV2::from_reader applique la même
    # borne de politique que le header v1.
    v2_002_total_len = 1024 * 2 + 300  # 3 chunks : 1024, 1024, 300 (dernier partiel)
    v2_002_plaintext = (v2_base_sentence * (v2_002_total_len // len(v2_base_sentence) + 2))[:v2_002_total_len]

    generate_vector_v2_external(
        name="v2_002",
        cek=bytes.fromhex("aa" * 16 + "bb" * 16),
        recipients=[
            (b"alice-key-fingerprint", b"wrapped-for-alice-0123456789abcdef"),
            (b"bob-key-fingerprint", b"wrapped-for-bob-0123456789abcdef"),
            (b"carol-key-fingerprint", b"wrapped-for-carol-0123456789abcdef"),
        ],
        base_nonce=bytes.fromhex("aabbccddeeff102132435465"),
        chunk_size=1024,
        plaintext=v2_002_plaintext,
        description="v2, key_source=1, 3 destinataires, plusieurs chunks (3), chunk_size=MIN_CHUNK_SIZE, dernier partiel (300 octets).",
    )

    # --- vector_v2_003 : v2, fichier vide -----------------------------------
    generate_vector_v2_external(
        name="v2_003",
        cek=bytes.fromhex("11" * 32),
        recipients=[(b"r1", b"w1")],
        base_nonce=bytes.fromhex("202122232425262728292a2b"),
        chunk_size=1024,
        plaintext=b"",
        description="v2, fichier vide : 1 chunk vide explicitement marque dernier.",
    )


if __name__ == "__main__":
    main()
