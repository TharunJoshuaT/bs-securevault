use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, ParamsBuilder};
use clap::{Parser, Subcommand};
use getrandom::getrandom;
use rpassword::prompt_password;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Parser)]
#[command(name = "bsv")]
#[command(about = "BS SecureVault — Standalone Native Terminal Encryption Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file into a .bsv container
    Encrypt {
        /// Path to input file
        #[arg(short, long)]
        input: PathBuf,

        /// Path to output file (defaults to <input>.bsv)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Decrypt a .bsv container back to original file
    Decrypt {
        /// Path to .bsv file
        #[arg(short, long)]
        input: PathBuf,

        /// Path to restored output file
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let mut key = [0u8; KEY_LEN];
    let params = ParamsBuilder::new()
        .m_cost(19456)
        .t_cost(2)
        .p_cost(1)
        .output_len(KEY_LEN)
        .build()
        .map_err(|e| format!("Argon2 params invalid: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    Ok(key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.bsv", input.display())));

            println!("🔒 Encrypting: {}", input.display());
            let mut passphrase = prompt_password("Enter Master Passphrase: ")?;
            let mut confirm_pass = prompt_password("Confirm Passphrase: ")?;

            if passphrase != confirm_pass {
                passphrase.zeroize();
                confirm_pass.zeroize();
                eprintln!("Error: Passphrases do not match.");
                std::process::exit(1);
            }

            let start = Instant::now();
            let data = fs::read(&input)?;

            let mut salt = [0u8; SALT_LEN];
            getrandom(&mut salt).map_err(|e| format!("Salt RNG failed: {}", e))?;

            let mut nonce_bytes = [0u8; NONCE_LEN];
            getrandom(&mut nonce_bytes).map_err(|e| format!("Nonce RNG failed: {}", e))?;

            let mut key = derive_key_argon2id(passphrase.as_bytes(), &salt)?;
            passphrase.zeroize();
            confirm_pass.zeroize();

            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e));
            key.zeroize(); // Immediate terminal RAM cleanup
            let cipher = cipher?;

            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, data.as_slice())
                .map_err(|_| "Encryption failed")?;

            let mut payload = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
            payload.extend_from_slice(&salt);
            payload.extend_from_slice(&nonce_bytes);
            payload.extend_from_slice(&ciphertext);

            fs::write(&out_path, payload)?;
            println!(
                "✓ Success! Encrypted payload written to {} ({:.2?})",
                out_path.display(),
                start.elapsed()
            );
        }

        Commands::Decrypt { input, output } => {
            println!("🔓 Decrypting: {}", input.display());
            let mut passphrase = prompt_password("Enter Master Passphrase: ")?;

            let start = Instant::now();
            let payload = fs::read(&input)?;

            if payload.len() < SALT_LEN + NONCE_LEN {
                passphrase.zeroize();
                eprintln!("Error: Invalid or truncated .bsv payload.");
                std::process::exit(1);
            }

            let salt = &payload[..SALT_LEN];
            let nonce_bytes = &payload[SALT_LEN..SALT_LEN + NONCE_LEN];
            let ciphertext = &payload[SALT_LEN + NONCE_LEN..];

            let mut key = derive_key_argon2id(passphrase.as_bytes(), salt)?;
            passphrase.zeroize();

            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher init failed: {}", e));
            key.zeroize(); // Immediate terminal RAM cleanup
            let cipher = cipher?;

            let nonce = Nonce::from_slice(nonce_bytes);

            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    fs::write(&output, plaintext)?;
                    println!(
                        "✓ Success! Restored file written to {} ({:.2?})",
                        output.display(),
                        start.elapsed()
                    );
                }
                Err(_) => {
                    eprintln!("ACCESS DENIED: Incorrect passphrase or corrupted payload.");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
