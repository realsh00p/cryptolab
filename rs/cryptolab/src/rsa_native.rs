use rand::rngs::OsRng;
use rsa::{BigUint, Oaep, RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use sha2::Sha256;

pub const DEFAULT_PUBLIC_EXPONENT: u64 = 65_537;
pub const DEFAULT_MODULUS_BITS: usize = 4_096;

pub struct KeyPair {
    private_key: RsaPrivateKey,
}

impl KeyPair {
    pub fn new(e: u64, modulus_bits: usize) -> Result<Self, String> {
        let private_key = RsaPrivateKey::new_with_exp(&mut OsRng, modulus_bits, &BigUint::from(e))
            .map_err(|error| format!("native RSA key generation failed: {error}"))?;
        Ok(Self { private_key })
    }

    pub fn default_rsa() -> Result<Self, String> {
        Self::new(DEFAULT_PUBLIC_EXPONENT, DEFAULT_MODULUS_BITS)
    }

    pub fn public_key(&self) -> (BigUint, BigUint) {
        let public = RsaPublicKey::from(&self.private_key);
        (public.e().clone(), public.n().clone())
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    pub fn encrypt(&self, plaintext: u64) -> Result<Vec<u8>, String> {
        let public = RsaPublicKey::from(&self.private_key);
        public
            .encrypt(
                &mut OsRng,
                Oaep::new::<Sha256>(),
                &encode_integer(plaintext),
            )
            .map_err(|error| format!("native RSA encryption failed: {error}"))
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<u64, String> {
        let encoded = self
            .private_key
            .decrypt(Oaep::new::<Sha256>(), ciphertext)
            .map_err(|error| format!("native RSA decryption failed: {error}"))?;
        decode_integer(&encoded)
    }
}

fn encode_integer(value: u64) -> Vec<u8> {
    let encoded = value.to_be_bytes();
    let first = encoded
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(encoded.len() - 1);
    encoded[first..].to_vec()
}

fn decode_integer(encoded: &[u8]) -> Result<u64, String> {
    if encoded.len() > size_of::<u64>() {
        return Err("decrypted plaintext does not fit in u64".into());
    }

    let mut padded = [0_u8; size_of::<u64>()];
    let start = padded.len() - encoded.len();
    padded[start..].copy_from_slice(encoded);
    Ok(u64::from_be_bytes(padded))
}
