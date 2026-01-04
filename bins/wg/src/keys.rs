//! Key generation commands for WireGuard.

use nlink::netlink::{Error, Result};
use rand::RngCore;
use std::io::{self, Read};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::output::{base64_decode, base64_encode};

/// Generate a new private key.
pub fn genkey() -> Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

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
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| Error::Io(e))?;

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
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    println!("{}", base64_encode(&key));
    Ok(())
}
