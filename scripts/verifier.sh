#!/usr/bin/env bash
# Vérifications avant une version (audit ANSSI du 24/10/2026, règles
# DENV-LINTER et LIBS-AUDIT) : pour chaque projet Rust du dépôt,
#   1. clippy sans aucun avertissement ;
#   2. cargo audit (vulnérabilités connues ; exceptions justifiées dans
#      .cargo/audit.toml) ;
#   3. tests.
# Les projets de fuzzing (toolchain nightly) ne passent que cargo audit.
#
# Prérequis : cargo install cargo-audit --locked
set -uo pipefail
cd "$(dirname "$0")/.."
RACINE="$(pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

PROJETS=(.)
AUDIT_SEUL=(core/fuzz)

echecs=()
etape() { # projet, nom de l'étape, commande…
    local projet="$1" nom="$2"; shift 2
    echo "==> $projet : $nom"
    if ! (cd "$RACINE/$projet" && "$@"); then
        echecs+=("$projet : $nom")
    fi
}

for p in "${PROJETS[@]}"; do
    etape "$p" clippy cargo clippy --workspace --all-targets --quiet -- -D warnings
    etape "$p" audit cargo audit --quiet
    etape "$p" tests cargo test --workspace --quiet
done
for p in "${AUDIT_SEUL[@]}"; do
    etape "$p" audit cargo audit --quiet
done

echo
if [ ${#echecs[@]} -eq 0 ]; then
    echo "OK : toutes les vérifications sont passées."
else
    echo "ÉCHEC :"
    printf '    %s\n' "${echecs[@]}"
    exit 1
fi
