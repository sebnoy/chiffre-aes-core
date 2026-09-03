#!/usr/bin/env python3
"""
Générateur INDÉPENDANT (Python) de vecteurs de test pour le format .enc
de chiffre_aes_core, à partir de la seule spécification FORMAT.md.

N'importe et ne dépend d'AUCUN code du crate Rust. Chaque appel à
`generate_vector(...)` produit un couple (vector_NNN.json, vector_NNN.enc)
et supporte un nombre arbitraire de chunks, contrairement à la version
initiale limitée à un seul chunk.

Dépendances : argon2-cffi, cryptography (deux bibliothèques indépendantes
de RustCrypto, chacune largement utilisée et testée séparément).
"""
import argon2.low_level as a2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import json
import math
import os

HEADER_NONCE_COUNTER = 0xFFFFFFFFFFFFFFFF  # u64::MAX


def derive_nonce(base_nonce: bytes, counter: int) -> bytes:
    """base_nonce XOR (0..0 || counter_be) sur les 8 derniers octets."""
    counter_bytes = counter.to_bytes(8, "big")
    out = bytearray(base_nonce)
    for i in range(8):
        out[4 + i] ^= counter_bytes[i]
    return bytes(out)


def build_header(salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
                  base_nonce, chunk_size, total_chunks, total_plaintext_size):
    h = b"ENC1"
    h += (1).to_bytes(1, "big")
    h += salt
    h += argon2_memory_kib.to_bytes(4, "big")
    h += argon2_iterations.to_bytes(4, "big")
    h += argon2_parallelism.to_bytes(1, "big")
    h += base_nonce
    h += chunk_size.to_bytes(4, "big")
    h += total_chunks.to_bytes(8, "big")
    h += total_plaintext_size.to_bytes(8, "big")
    assert len(h) == 62, f"header doit faire 62 octets, obtenu {len(h)}"
    return h


def generate_vector(name: str, password: bytes, salt: bytes, base_nonce: bytes,
                     argon2_memory_kib: int, argon2_iterations: int,
                     argon2_parallelism: int, chunk_size: int, plaintext: bytes,
                     description: str):
    assert len(salt) == 16, f"salt doit faire 16 octets, obtenu {len(salt)}"
    assert len(base_nonce) == 12, f"base_nonce doit faire 12 octets, obtenu {len(base_nonce)}"

    key = a2.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=argon2_iterations,
        memory_cost=argon2_memory_kib,
        parallelism=argon2_parallelism,
        hash_len=32,
        type=a2.Type.ID,
        version=19,  # 0x13, doit correspondre a argon2::Version::V0x13 cote Rust
    )

    # Meme regle que expected_plaintext_len() cote Rust : un fichier vide
    # produit tout de meme 1 chunk (vide), explicitement marque "dernier".
    total_plaintext_size = len(plaintext)
    total_chunks = 1 if total_plaintext_size == 0 else math.ceil(total_plaintext_size / chunk_size)

    header = build_header(salt, argon2_memory_kib, argon2_iterations,
                           argon2_parallelism, base_nonce, chunk_size,
                           total_chunks, total_plaintext_size)

    aesgcm = AESGCM(key)

    header_nonce = derive_nonce(base_nonce, HEADER_NONCE_COUNTER)
    header_tag = aesgcm.encrypt(header_nonce, b"", header)
    assert len(header_tag) == 16

    header_hash = hashlib.sha256(header + header_tag).digest()

    chunks = []
    enc_file = bytearray(header + header_tag)
    offset = 0
    for index in range(total_chunks):
        is_last = (index == total_chunks - 1)
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

    vector = {
        "description": description,
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
            "full_enc_file_hex": bytes(enc_file).hex(),
        },
    }

    # Chemin relatif vers le dossier de destination (core/tests/vectors)
    output_dir = os.path.join("..", "tests", "vectors")


    for name in ["001", "002", "003"]: 
        # Chemin complet pour les fichiers
        vector_json_path = os.path.join(output_dir, f"vector_{name}.json")
        vector_enc_path = os.path.join(output_dir, f"vector_{name}.enc")

        # Écrire les fichiers
        with open(vector_json_path, "w") as f:
            json.dump(vector, f, indent=2)

        with open(vector_enc_path, "wb") as f:
            f.write(bytes(enc_file))


    print(f"vector_{name}: {total_chunks} chunk(s), fichier .enc de {len(enc_file)} octets")


def main():
    # --- vector_001 : un seul chunk (cas deja existant, memes entrees) ---
    generate_vector(
        name="001",
        password=b"mot-de-passe-vecteur-test-independant-01",
        salt=bytes.fromhex("00112233445566778899aabbccddeeff"),
        base_nonce=bytes.fromhex("0102030405060708090a0b0c"),
        argon2_memory_kib=8 * 1024,
        argon2_iterations=1,
        argon2_parallelism=1,
        chunk_size=1024 * 1024,
        plaintext=b"Ceci est un vecteur de test independant pour chiffre-aes-core.\n",
        description="Cas nominal, un seul chunk.",
    )

    # --- vector_002 : plusieurs chunks, dernier chunk partiel ------------
    generate_vector(
        name="002",
        password=b"mot-de-passe-vecteur-test-independant-02",
        salt=bytes.fromhex("112233445566778899aabbccddeeff00"),
        base_nonce=bytes.fromhex("aabbccddeeff001122334455"),
        argon2_memory_kib=8 * 1024,
        argon2_iterations=1,
        argon2_parallelism=1,
        chunk_size=16,  # volontairement petit pour forcer plusieurs chunks
        plaintext=(
            b"Vecteur multi-chunks : chaque chunk authentifie son index "
            b"et sa position finale dans le flux.\n"
        ),
        description="Plusieurs chunks (6), dernier chunk partiel (14 octets).",
    )

    # --- vector_003 : fichier vide (1 chunk vide, marque dernier) --------
    generate_vector(
        name="003",
        password=b"mot-de-passe-vecteur-test-independant-03",
        salt=bytes.fromhex("ffeeddccbbaa00112233445566778899"[:32]),
        base_nonce=bytes.fromhex("000000000000000000000001"),
        argon2_memory_kib=8 * 1024,
        argon2_iterations=1,
        argon2_parallelism=1,
        chunk_size=1024,
        plaintext=b"",
        description="Fichier vide : 1 chunk vide explicitement marque dernier.",
    )


if __name__ == "__main__":
    main()
