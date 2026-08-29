#!/usr/bin/env bash
# Build statique Linux (x86_64-unknown-linux-musl) — Lot 9.
#
# Ce script ne construit QUE chiffre_aes_cli. chiffre_aes_gui ne peut pas être construit en
# musl statique (+crt-static) : Winit charge les bibliothèques graphiques
# système (Wayland, X11, xkbcommon...) au runtime via dlopen(), ce qui
# nécessite un chargeur dynamique — absent d'un exécutable totalement
# statique. Le binaire compile sans erreur mais échoue systématiquement à
# l'exécution ("Could not initialize backend"), quel que soit
# l'environnement graphique de la machine cible.
# Pour chiffre_aes_gui, voir ./scripts/build-appimage.sh (packaging AppImage :
# distribution en un seul fichier, sans installation, en gardant un lien
# dynamique classique).
#
# À exécuter sur une machine disposant de `rustup` et d'un accès réseau
# normal (contrairement à l'environnement sandbox où ce projet a été
# développé, qui n'a pas accès à static.rust-lang.org et ne peut donc pas
# récupérer les bibliothèques standard pour les cibles croisées — voir
# README, section Lot 9).
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
