//! Key generation commands for WireGuard.

use std::io::{self, Read};

use nlink::netlink::{Error, Result};
use rand::CryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::output::{base64_decode, base64_encode};

/// Fill a fixed-size buffer with cryptographically secure random
/// bytes from the thread RNG.
///
/// The `CryptoRng` bound is load-bearing rather than decorative: it
/// is a compile-time assertion that whatever `rand::rng()` resolves
/// to is a CSPRNG. rand has moved this corner of its API twice now
/// (`thread_rng()` -> `rng()`, `RngCore` -> `Rng`), and a future move
/// that quietly handed back a non-cryptographic generator would still
/// produce perfectly plausible-looking WireGuard keys — with no test,
/// no panic, and no way to tell from the output.
fn secure_random_bytes<const N: usize>() -> [u8; N] {
    fn fill<R: CryptoRng>(rng: &mut R, dst: &mut [u8]) {
        rng.fill_bytes(dst);
    }
    let mut buf = [0u8; N];
    fill(&mut rand::rng(), &mut buf);
    buf
}

/// Generate a new private key.
pub fn genkey() -> Result<()> {
    let mut key: [u8; 32] = secure_random_bytes();

    // Clamp for Curve25519 (this is what WireGuard expects)
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;

    println!("{}", base64_encode(&key));
    Ok(())
}

/// Derive public key from private key read from stdin.
pub fn pubkey() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(Error::Io)?;

    let private_bytes = base64_decode(&input)
        .map_err(|e| Error::InvalidMessage(format!("Invalid base64: {}", e)))?;

    if private_bytes.len() != 32 {
        return Err(Error::InvalidMessage(format!(
            "Invalid private key length: expected 32, got {}",
            private_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&private_bytes);

    let secret = StaticSecret::from(key);
    let public = PublicKey::from(&secret);

    println!("{}", base64_encode(public.as_bytes()));
    Ok(())
}

/// Generate a preshared key.
pub fn genpsk() -> Result<()> {
    let key: [u8; 32] = secure_random_bytes();

    println!("{}", base64_encode(&key));
    Ok(())
}
