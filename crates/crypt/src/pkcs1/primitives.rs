use num_bigint::BigUint;

use super::{PrivateKey, PublicKey};

/// Integer to Octet string
/// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.1>
pub(super) fn int_to_octets(value: &BigUint, len: usize) -> Box<[u8]> {
    let octets = value.to_bytes_be();
    assert!(len >= octets.len());
    let mut v = vec![0; len - octets.len()];
    v.extend(octets);
    v.into_boxed_slice()
}

/// Octet string to Integer
/// <https://datatracker.ietf.org/doc/html/rfc8017#section-4.2>
pub(super) fn octets_to_int(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.1.1>
pub(super) fn rsa_ep(key: &PublicKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.1.2>
pub(super) fn rsa_dp(key: &PrivateKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.1>
pub(super) fn rsa_sp1(key: &PrivateKey, msg_repr: &BigUint) -> BigUint {
    msg_repr.modpow(&key.exponent, &key.modulus)
}

/// <https://datatracker.ietf.org/doc/html/rfc8017#section-5.2.2>
pub(super) fn rsa_vp1(key: &PublicKey, sgn_repr: &BigUint) -> BigUint {
    assert!(*sgn_repr < key.modulus);
    sgn_repr.modpow(&key.exponent, &key.modulus)
}
