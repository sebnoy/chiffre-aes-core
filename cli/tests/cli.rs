//! Essais de la CLI compilée, mot de passe fourni par un tube (une ligne par réponse).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CLI: &str = env!("CARGO_BIN_EXE_chiffre_aes_cli");
const FORT: &str = "Essai-de-la-CLI-2026!";

/// Dossier de travail propre à chaque essai (sans dépendance de test supplémentaire).
fn dossier(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("chiffre_aes_cli-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn lancer(args: &[&Path], entree: &str) -> Output {
    let mut p = Command::new(CLI)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    p.stdin
        .take()
        .unwrap()
        .write_all(entree.as_bytes())
        .unwrap();
    p.wait_with_output().unwrap()
}

fn erreur(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn source(d: &Path) -> PathBuf {
    let f = d.join("source.txt");
    std::fs::write(&f, "contenu à protéger").unwrap();
    f
}

#[test]
fn chiffrement_puis_dechiffrement() {
    let d = dossier("aller-retour");
    let (src, enc, sortie) = (source(&d), d.join("a.enc"), d.join("sortie"));
    let o = lancer(
        &[Path::new("encrypt"), &enc, &src],
        &format!("{FORT}\n{FORT}\n"),
    );
    assert!(o.status.success(), "{}", erreur(&o));
    let o = lancer(&[Path::new("decrypt"), &enc, &sortie], &format!("{FORT}\n"));
    assert!(o.status.success(), "{}", erreur(&o));
    assert_eq!(
        std::fs::read_to_string(sortie.join("source.txt")).unwrap(),
        "contenu à protéger"
    );
}

#[test]
fn confirmation_differente_refusee_et_rien_ecrit() {
    let d = dossier("confirmation");
    let (src, enc) = (source(&d), d.join("a.enc"));
    let o = lancer(
        &[Path::new("encrypt"), &enc, &src],
        &format!("{FORT}\n{FORT}x\n"),
    );
    assert!(!o.status.success());
    assert!(
        erreur(&o).contains("ne correspondent pas"),
        "{}",
        erreur(&o)
    );
    assert!(!enc.exists());
}

#[test]
fn confirmation_absente_refusee() {
    let d = dossier("sans-confirmation");
    let (src, enc) = (source(&d), d.join("a.enc"));
    let o = lancer(&[Path::new("encrypt"), &enc, &src], &format!("{FORT}\n"));
    assert!(!o.status.success());
    assert!(!enc.exists());
}

#[test]
fn mot_de_passe_faible_ou_court_refuse() {
    let d = dossier("faible");
    let (src, enc) = (source(&d), d.join("a.enc"));
    let o = lancer(&[Path::new("encrypt"), &enc, &src], "abc\nabc\n");
    assert!(!o.status.success());
    assert!(erreur(&o).contains("trop court"), "{}", erreur(&o));
    let o = lancer(
        &[Path::new("encrypt"), &enc, &src],
        "motdepasse12\nmotdepasse12\n",
    );
    assert!(!o.status.success());
    assert!(erreur(&o).contains("trop faible"), "{}", erreur(&o));
    assert!(!enc.exists());
}

#[test]
fn mauvais_mot_de_passe_au_dechiffrement() {
    let d = dossier("mauvais");
    let (src, enc, sortie) = (source(&d), d.join("a.enc"), d.join("sortie"));
    assert!(lancer(
        &[Path::new("encrypt"), &enc, &src],
        &format!("{FORT}\n{FORT}\n")
    )
    .status
    .success());
    let o = lancer(
        &[Path::new("decrypt"), &enc, &sortie],
        "faux-mot-de-passe\n",
    );
    assert!(!o.status.success());
    assert!(
        erreur(&o).contains("mot de passe incorrect"),
        "{}",
        erreur(&o)
    );
}
