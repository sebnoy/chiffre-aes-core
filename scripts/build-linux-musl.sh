#!/usr/bin/env bash
# Build statique Linux (x86_64-unknown-linux-musl) 
#
# Ce script construit chiffre_aes_cli.
# À exécuter sur une machine disposant de `rustup` et d'un accès réseau

#
# Usage :
#   ./scripts/build-linux-musl.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl

if [ "${1:-}" = "gui" ]; then
    echo "ERREUR : chiffre_aes_gui ne peut pas être construit en musl statique." >&2
    echo "  Winit dlopen() les libs graphiques système (Wayland/X11) au" >&2
    echo "  runtime ; un binaire +crt-static n'a pas de chargeur dynamique" >&2
    echo "  et échoue toujours à l'exécution, quel que soit le système." >&2
    echo "  Utilisez ./scripts/build-appimage.sh pour chiffre_aes_gui." >&2
    exit 1
fi

echo "==> Vérification du toolchain"
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "    Cible $TARGET absente, installation..."
    rustup target add "$TARGET"
fi
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "ERREUR : musl-gcc introuvable. Installez le paquet 'musl-tools'" >&2
    echo "  (Debian/Ubuntu : sudo apt install musl-tools)" >&2
    exit 1
fi

echo "==> Compilation en release pour $TARGET"
crate=chiffre_aes_cli
echo "---- $crate ----"
cargo build --release --target "$TARGET" -p "$crate"

bin="target/$TARGET/release/$crate"
echo "==> Vérification des dépendances dynamiques ($crate)"
if command -v ldd >/dev/null 2>&1; then
    if ldd "$bin" 2>&1 | grep -q "not a dynamic executable"; then
        echo "    OK : binaire statique, aucune dépendance dynamique."
    else
        echo "    ATTENTION : des dépendances dynamiques subsistent :"
        ldd "$bin" || true
        echo "    Ceci ne devrait pas arriver avec la cible musl ; vérifier"
        echo "    qu'aucune dépendance ne force un lien dynamique (ex. via"
        echo "    une feature cargo non désirée)."
    fi
fi
echo "    Binaire : $bin ($(du -h "$bin" | cut -f1))"

echo "==> Terminé."
