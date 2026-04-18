use num_bigint::BigUint;

mod emsa;
mod mgf;
mod primitives;
mod rsassa;

pub use rsassa::{rsassa_pss_sign, rsassa_pss_verify};

pub struct PublicKey {
    /// RSA modulus (n)
    pub modulus: BigUint,
    /// Public exponent (e)
    pub exponent: BigUint,
}

pub struct PrivateKey {
    /// RSA modulus (n)
    pub modulus: BigUint,
    /// Private exponent (d)
    pub exponent: BigUint,
}
