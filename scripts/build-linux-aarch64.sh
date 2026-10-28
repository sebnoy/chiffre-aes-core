#!/usr/bin/env bash
# Build de chiffre_aes_cli pour Raspberry Pi 64 bits (aarch64-unknown-linux-gnu), en
# compilation croisée depuis un PC x86_64 Debian/Ubuntu.
#
# Lien dynamique classique avec la glibc (pas de musl : la chaîne croisée musl n'est pas
# empaquetée sous Debian/Ubuntu). Le binaire tourne sur toute distribution aarch64 dont la
# glibc est au moins celle indiquée à la fin (Raspberry Pi OS Bookworm : 2.36, Trixie : 2.41).
#
# Prérequis :
#   rustup target add aarch64-unknown-linux-gnu
#   sudo apt install gcc-aarch64-linux-gnu
#
# Usage :
#   ./scripts/build-linux-aarch64.sh
# Résultat : target/aarch64-unknown-linux-gnu/release/chiffre_aes_cli
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=aarch64-unknown-linux-gnu
LINKER=aarch64-linux-gnu-gcc
crate=chiffre_aes_cli

echo "==> Vérification du toolchain"
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "    Cible $TARGET absente, installation..."
    rustup target add "$TARGET"
fi
if ! command -v "$LINKER" >/dev/null 2>&1; then
    echo "ERREUR : $LINKER introuvable. Installez le paquet 'gcc-aarch64-linux-gnu'" >&2
    echo "  (Debian/Ubuntu : sudo apt install gcc-aarch64-linux-gnu)" >&2
    exit 1
fi

echo "==> Compilation en release pour $TARGET"
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$LINKER" \
    cargo build --release --target "$TARGET" -p "$crate"

bin="target/$TARGET/release/$crate"
echo "==> Vérification du binaire"
if command -v file >/dev/null 2>&1; then
    file "$bin" | grep -q "ARM aarch64" || { echo "ERREUR : $bin n'est pas un binaire aarch64" >&2; exit 1; }
fi
glibc="$(aarch64-linux-gnu-objdump -T "$bin" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -n 1 || true)"
echo "    OK : $bin"
echo "    glibc minimale requise : ${glibc:-inconnue}"
