use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use zeroize::Zeroize;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.bsv", input.display())));

            println!("Encrypting: {}", input.display());
            let mut passphrase = prompt_password("Enter Master Passphrase: ")?;
            let mut confirm_pass = prompt_password("Confirm Passphrase: ")?;

            if passphrase != confirm_pass {
                passphrase.zeroize();
                confirm_pass.zeroize();
                eprintln!("Error: Passphrases do not match.");
                std::process::exit(1);
            }
            confirm_pass.zeroize();

            let start = Instant::now();
            let data = fs::read(&input)?;

            let encrypted = match bs_securevault::encrypt_core(&data, passphrase.as_bytes()) {
                Ok(buf) => {
                    passphrase.zeroize();
                    buf
                }
                Err(err) => {
                    passphrase.zeroize();
                    eprintln!("Encryption failed: {:?}", err);
                    std::process::exit(1);
                }
            };

            fs::write(&out_path, encrypted)?;
            println!(
                "Success! Encrypted payload written to {} ({:.2?})",
                out_path.display(),
                start.elapsed()
            );
        }

        Commands::Decrypt { input, output } => {
            println!("Decrypting: {}", input.display());
            let mut passphrase = prompt_password("Enter Master Passphrase: ")?;

            let start = Instant::now();
            let payload = fs::read(&input)?;

            let plaintext = match bs_securevault::decrypt_core(&payload, passphrase.as_bytes()) {
                Ok(buf) => {
                    passphrase.zeroize();
                    buf
                }
                Err(err) => {
                    passphrase.zeroize();
                    eprintln!("ACCESS DENIED: {:?} — Incorrect passphrase or corrupted/tampered payload.", err);
                    std::process::exit(1);
                }
            };

            fs::write(&output, plaintext)?;
            println!(
                "Success! Restored file written to {} ({:.2?})",
                output.display(),
                start.elapsed()
            );
        }
    }

    Ok(())
}
