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

/// Clamp a 32-byte scalar for Curve25519, as WireGuard expects to
/// find on the wire.
///
/// X25519 clamps internally during scalar-point multiplication, so
/// this does not change any key we derive — it is about the bytes
/// `genkey` prints, which other implementations read.
fn clamp(key: &mut [u8; 32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

/// Generate a new private key.
pub fn genkey() -> Result<()> {
    let mut key: [u8; 32] = secure_random_bytes();
    clamp(&mut key);

    println!("{}", base64_encode(&key));
    Ok(())
}

/// Derive the X25519 public key for a private key.
///
/// Split out from [`pubkey`] so it can be checked against known
/// answers — `pubkey` itself reads stdin and prints, which is not
/// something a test can pin.
fn derive_public(private: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(private);
    PublicKey::from(&secret).to_bytes()
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

    println!("{}", base64_encode(&derive_public(key)));
    Ok(())
}

/// Generate a preshared key.
pub fn genpsk() -> Result<()> {
    let key: [u8; 32] = secure_random_bytes();

    println!("{}", base64_encode(&key));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer tests from RFC 7748 §6.1.
    ///
    /// This is the one thing standing between a `x25519-dalek` major
    /// bump and silently wrong keys. Everything else about a key is
    /// unfalsifiable by inspection: a public key derived by a subtly
    /// different curve implementation is still 32 plausible-looking
    /// bytes, still base64-encodes, still round-trips — and produces
    /// a tunnel that simply never handshakes.
    ///
    /// Added during the 2.x -> 3.0 bump, whose changelog claims no
    /// change to the derivation. This checks that claim rather than
    /// trusting it.
    #[test]
    fn derive_public_matches_rfc7748_vectors() {
        // Alice
        let a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let a_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(derive_public(a), a_pub, "RFC 7748 Alice");

        // Bob
        let b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let b_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(derive_public(b), b_pub, "RFC 7748 Bob");
    }

    /// The RFC vectors are deliberately *not* clamped, and X25519
    /// clamps internally during scalar multiplication. So clamping
    /// the input first must not move the answer — if it did, `genkey`
    /// (which clamps) and a key from another implementation (which
    /// may not) would derive different public keys from the same
    /// private key.
    #[test]
    fn clamping_the_input_does_not_change_the_derived_key() {
        let mut a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let unclamped = derive_public(a);
        clamp(&mut a);
        assert_ne!(
            a,
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            "the RFC vector should not already be clamped, or this proves nothing"
        );
        assert_eq!(derive_public(a), unclamped);
    }

    #[test]
    fn clamp_sets_the_bits_curve25519_requires() {
        for seed in 0u8..=255 {
            let mut key = [seed; 32];
            clamp(&mut key);
            assert_eq!(key[0] & 7, 0, "low 3 bits must be clear");
            assert_eq!(key[31] & 128, 0, "high bit must be clear");
            assert_eq!(key[31] & 64, 64, "second-highest bit must be set");
        }
    }

    /// `genkey` prints a clamped key; `pubkey` must accept exactly
    /// that and round-trip through the base64 layer both use.
    #[test]
    fn generated_keys_round_trip_through_base64() {
        let mut key: [u8; 32] = secure_random_bytes();
        clamp(&mut key);

        let encoded = base64_encode(&key);
        let decoded = base64_decode(&encoded).expect("genkey output must decode");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded[..], key[..]);

        // And the public key derived from it is stable.
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(&decoded);
        assert_eq!(derive_public(fixed), derive_public(key));
    }

    /// Two independently generated keys must differ — a stuck or
    /// zeroed RNG would otherwise sail through every test above.
    #[test]
    fn generated_keys_are_not_constant() {
        let a: [u8; 32] = secure_random_bytes();
        let b: [u8; 32] = secure_random_bytes();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
        }
        out
    }
}
