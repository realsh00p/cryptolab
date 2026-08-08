use cryptolab::{rsa_diy, rsa_native};
use std::{process::ExitCode, time::Instant};

fn run_diy() -> Result<(), String> {
    let alice = rsa_diy::KeyPair::default_rsa()?;
    let bob = rsa_diy::KeyPair::default_rsa()?;

    let for_alice = 123_456_789;
    let ciphertext = alice.encrypt(for_alice)?;
    let plaintext = alice.decrypt(&ciphertext)?;
    if plaintext != for_alice {
        return Err("DIY decrypted plaintext does not match".into());
    }
    eprintln!("INFO DIY decrypted plaintext: {plaintext}");

    let for_bob = 987_654_321;
    let ciphertext = bob.encrypt(for_bob)?;
    let plaintext = bob.decrypt(&ciphertext)?;
    if plaintext != for_bob {
        return Err("DIY decrypted plaintext does not match".into());
    }
    eprintln!("INFO DIY decrypted plaintext: {plaintext}");
    Ok(())
}

fn run_native() -> Result<(), String> {
    let alice = rsa_native::KeyPair::default_rsa()?;
    let bob = rsa_native::KeyPair::default_rsa()?;

    let for_alice = 123_456_789;
    let ciphertext = alice.encrypt(for_alice)?;
    let plaintext = alice.decrypt(&ciphertext)?;
    if plaintext != for_alice {
        return Err("Native decrypted plaintext does not match".into());
    }
    eprintln!("INFO Native decrypted plaintext: {plaintext}");

    let for_bob = 987_654_321;
    let ciphertext = bob.encrypt(for_bob)?;
    let plaintext = bob.decrypt(&ciphertext)?;
    if plaintext != for_bob {
        return Err("Native decrypted plaintext does not match".into());
    }
    eprintln!("INFO Native decrypted plaintext: {plaintext}");
    Ok(())
}

fn main() -> ExitCode {
    let tick = Instant::now();
    if let Err(error) = run_diy() {
        eprintln!("ERROR {error}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "INFO DIY RSA elapsed: {:.6} seconds",
        tick.elapsed().as_secs_f64()
    );

    let tick = Instant::now();
    if let Err(error) = run_native() {
        eprintln!("ERROR {error}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "INFO Native RSA elapsed: {:.6} seconds",
        tick.elapsed().as_secs_f64()
    );
    ExitCode::SUCCESS
}
