//! CLI — chiffrement/déchiffrement d'une sélection de fichiers et/ou de
//! dossiers, via `chiffre_aes_core::pipeline`.
//!
//! Usage :
//!   chiffre_aes_cli encrypt <sortie.enc> <source1> [source2 ...]
//!   chiffre_aes_cli decrypt <source.enc> <dossier_sortie>
//!   chiffre_aes_cli check-password
//!
//! `check-password` permet d'évaluer un mot de passe (longueur, score
//! `zxcvbn`, correspondance de confirmation) indépendamment de toute
//! opération de chiffrement — pratique pour tester la politique de mot de
//! passe sans passer par la GUI.

use chiffre_aes_core::pipeline::{decrypt_to_dir, encrypt_paths, PipelineError};
use chiffre_aes_core::{assess_password, passwords_match, Argon2Params, FormatError};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return ExitCode::FAILURE;
    }

    let command = args[1].as_str();

    if command == "check-password" {
        return run_check_password();
    }

    let password = match read_password("Mot de passe : ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Erreur système : {e}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = match command {
        "encrypt" => {
            if args.len() < 4 {
                print_usage(&args[0]);
                return ExitCode::FAILURE;
            }
            let output_enc = PathBuf::from(&args[2]);
            let sources: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
            encrypt_paths(&sources, &output_enc, &password, Argon2Params::default())
                .map(|warnings| {
                    print_warnings(&warnings);
                    "Chiffrement réussi.".to_string()
                })
        }
        "decrypt" => {
            if args.len() != 4 {
                print_usage(&args[0]);
                return ExitCode::FAILURE;
            }
            let input_enc = PathBuf::from(&args[2]);
            let dest_dir = PathBuf::from(&args[3]);
            decrypt_to_dir(&input_enc, &dest_dir, &password).map(|warnings| {
                print_warnings(&warnings);
                "Déchiffrement réussi.".to_string()
            })
        }
        other => {
            eprintln!("Commande inconnue : {other} (attendu : encrypt | decrypt)");
            return ExitCode::FAILURE;
        }
    };

    match outcome {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        // Messages distincts par nature d'erreur.
        Err(PipelineError::Format(FormatError::WrongPassword)) => {
            eprintln!("Erreur : mot de passe incorrect.");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::Corrupted)) => {
            eprintln!("Erreur : fichier corrompu ou altéré.");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::Truncated)) => {
            eprintln!("Erreur : fichier tronqué (données manquantes).");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::Cancelled)) => {
            eprintln!("Erreur : opération annulée.");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::InvalidHeader)) => {
            eprintln!("Erreur : ce fichier n'est pas une archive .enc valide.");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::Io(e))) => {
            eprintln!("Erreur système : {e}");
            ExitCode::FAILURE
        }
        Err(PipelineError::Format(FormatError::Crypto(e))) => {
            eprintln!("Erreur cryptographique interne : {e}");
            ExitCode::FAILURE
        }
        Err(PipelineError::Archive(e)) => {
            eprintln!("Erreur d'archivage : {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_warnings(warnings: &[chiffre_aes_core::ArchiveWarning]) {
    for w in warnings {
        eprintln!("Avertissement : {} — {}", w.path.display(), w.reason);
    }
}

fn print_usage(prog: &str) {
    eprintln!("Usage :");
    eprintln!("  {prog} encrypt <sortie.enc> <source1> [source2 ...]");
    eprintln!("  {prog} decrypt <source.enc> <dossier_sortie>");
    eprintln!("  {prog} check-password");
}

fn run_check_password() -> ExitCode {
    let password = match read_password("Nouveau mot de passe : ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Erreur système : {e}");
            return ExitCode::FAILURE;
        }
    };
    let confirmation = match read_password("Confirmez le mot de passe : ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Erreur système : {e}");
            return ExitCode::FAILURE;
        }
    };

    let assessment = assess_password(&password);
    println!(
        "Score : {}/4 ({}) — longueur minimale {} : {}",
        assessment.score,
        assessment.label,
        chiffre_aes_core::MIN_LENGTH,
        if assessment.meets_min_length { "ok" } else { "insuffisante" }
    );
    if let Some(w) = &assessment.warning {
        println!("Avertissement : {w}");
    }
    for s in &assessment.suggestions {
        println!("Suggestion : {s}");
    }

    if !passwords_match(&password, &confirmation) {
        eprintln!("Erreur : les deux saisies ne correspondent pas.");
        return ExitCode::FAILURE;
    }

    if assessment.is_acceptable() {
        println!("Mot de passe accepté (bouton de validation activé).");
        ExitCode::SUCCESS
    } else {
        eprintln!("Mot de passe refusé : robustesse insuffisante (bouton de validation désactivé).");
        ExitCode::FAILURE
    }
}

/// Lecture du mot de passe sur stdin. Le buffer intermédiaire est effacé
/// dès qu'il n'est plus utile.
fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim_end_matches(['\n', '\r']).to_string();
    buf.zeroize();
    Ok(Zeroizing::new(trimmed))
}
