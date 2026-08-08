use rand::{RngCore, rngs::OsRng};
use rug::{Complete, Integer, integer::IsPrime, integer::Order};

pub const DEFAULT_PUBLIC_EXPONENT: u64 = 65_537;
pub const DEFAULT_MODULUS_BITS: u32 = 4_096;

pub struct KeyPair {
    e: u64,
    modulus: Integer,
    d: Integer,
}

impl KeyPair {
    pub fn new(e: u64, modulus_bits: u32) -> Result<Self, String> {
        if e <= 1 || e.is_multiple_of(2) {
            return Err("e must be an odd integer greater than 1".into());
        }
        if modulus_bits < 16 {
            return Err("modulus size must be at least 16 bits".into());
        }

        let p_bits = modulus_bits / 2;
        let q_bits = modulus_bits - p_bits;
        let p = generate_prime(p_bits, e)?;
        let q = loop {
            let candidate = generate_prime(q_bits, e)?;
            if candidate != p {
                break candidate;
            }
        };

        let modulus = Integer::from(&p * &q);
        let phi = Integer::from(&p - 1) * Integer::from(&q - 1);
        let d = Integer::from(e)
            .invert(&phi)
            .map_err(|_| "public exponent is not invertible modulo phi(N)".to_owned())?;

        Ok(Self { e, modulus, d })
    }

    pub fn default_rsa() -> Result<Self, String> {
        Self::new(DEFAULT_PUBLIC_EXPONENT, DEFAULT_MODULUS_BITS)
    }

    pub fn public_key(&self) -> (u64, &Integer) {
        (self.e, &self.modulus)
    }

    pub fn private_key(&self) -> (&Integer, &Integer) {
        (&self.d, &self.modulus)
    }

    pub fn encrypt(&self, plaintext: u64) -> Result<Integer, String> {
        Integer::from(plaintext)
            .pow_mod(&Integer::from(self.e), &self.modulus)
            .map_err(|_| "DIY RSA encryption failed".to_owned())
    }

    pub fn decrypt(&self, ciphertext: &Integer) -> Result<u64, String> {
        ciphertext
            .clone()
            .pow_mod(&self.d, &self.modulus)
            .map_err(|_| "DIY RSA decryption failed".to_owned())?
            .to_u64()
            .ok_or_else(|| "decrypted plaintext does not fit in u64".to_owned())
    }
}

fn generate_prime(bits: u32, e: u64) -> Result<Integer, String> {
    if bits < 2 {
        return Err("prime size must be at least 2 bits".into());
    }

    let mut random_bytes = vec![0_u8; bits.div_ceil(8) as usize];
    let exponent = Integer::from(e);

    loop {
        OsRng
            .try_fill_bytes(&mut random_bytes)
            .map_err(|error| format!("OS random-number generation failed: {error}"))?;

        let mut candidate = Integer::from_digits(&random_bytes, Order::MsfBe);
        candidate.keep_bits_mut(bits);
        candidate.set_bit(bits - 1, true);
        candidate.set_bit(bits - 2, true);
        candidate.set_bit(0, true);

        let mut candidate_minus_one = candidate.clone();
        candidate_minus_one -= 1;
        if candidate_minus_one.gcd_ref(&exponent).complete() != 1 {
            continue;
        }

        if candidate.is_probably_prime(40) != IsPrime::No {
            return Ok(candidate);
        }
    }
}
