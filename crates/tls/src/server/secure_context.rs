use crate::protocol::{
    hkdf::{hkdf_expand_label, hkdf_extract},
    record::{TlsCiphertext, TlsPlaintext},
};

use anyhow::Result;
use crypt::hash::Hasher;

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

const H_LENGTH: usize = 48; // Sha384
const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 12;

fn xor<const N: usize>(mut a: [u8; N], b: [u8; N]) -> [u8; N] {
    for i in 0..N {
        a[i] ^= b[i];
    }
    a
}

pub struct Transcript<H: Hasher> {
    inner: Vec<u8>,
    _hash: PhantomData<H>,
}

impl<H: Hasher> Transcript<H> {
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            _hash: PhantomData,
        }
    }

    pub fn extend(&mut self, plaintext: &TlsPlaintext) {
        self.inner.extend(&plaintext.to_raw()[5..]);
    }

    pub fn extend_raw(&mut self, raw: &[u8]) {
        self.inner.extend(raw);
    }

    pub fn hash(&self) -> [u8; H_LENGTH] {
        H::hash(&self.inner).as_ref().try_into().unwrap()
    }
}

pub struct TlsHandshakeSecureContext<H: Hasher> {
    seq_server_nonce: AtomicU64,
    seq_client_nonce: AtomicU64,

    pub handshake_secret: [u8; H_LENGTH],

    pub server_handshake_secret: [u8; H_LENGTH],
    pub server_handshake_key: [u8; KEY_LENGTH],
    pub server_handshake_iv: [u8; IV_LENGTH],

    pub client_handshake_secret: [u8; H_LENGTH],
    pub client_handshake_key: [u8; KEY_LENGTH],
    pub client_handshake_iv: [u8; IV_LENGTH],

    _hash: PhantomData<H>,
}

impl<H: Hasher> TlsHandshakeSecureContext<H> {
    pub fn new(
        key_ecdhe: Option<&[u8]>,
        key_psk: Option<&[u8]>,
        transcript_hash: [u8; H_LENGTH],
    ) -> Result<Self> {
        let empty_hash = H::hash(&[]);

        let early_secret = hkdf_extract::<H>(&[0; H_LENGTH], key_psk.unwrap_or(&[0; H_LENGTH]));
        let derived_secret =
            hkdf_expand_label::<H, H_LENGTH>(&early_secret, "derived", &empty_hash)?;
        let handshake_secret: [u8; H_LENGTH] =
            hkdf_extract::<H>(&derived_secret, key_ecdhe.unwrap_or(&[0; 32]))
                .as_ref()
                .try_into()?;

        // ## Server
        let server_handshake_secret =
            hkdf_expand_label::<H, H_LENGTH>(&handshake_secret, "s hs traffic", &transcript_hash)?;
        let server_handshake_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&server_handshake_secret, "key", &[])?;
        let server_handshake_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&server_handshake_secret, "iv", &[])?;

        // ## Client
        let client_handshake_secret =
            hkdf_expand_label::<H, H_LENGTH>(&handshake_secret, "c hs traffic", &transcript_hash)?;
        let client_handshake_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&client_handshake_secret, "key", &[])?;
        let client_handshake_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&client_handshake_secret, "iv", &[])?;

        Ok(Self {
            seq_server_nonce: AtomicU64::new(0),
            seq_client_nonce: AtomicU64::new(0),
            handshake_secret,
            server_handshake_secret,
            server_handshake_key,
            server_handshake_iv,
            client_handshake_secret,
            client_handshake_key,
            client_handshake_iv,
            _hash: PhantomData,
        })
    }

    pub fn server_nonce<const L: usize>(&self) -> [u8; L] {
        let nonce = self.seq_server_nonce.fetch_add(1, Ordering::Relaxed);

        let mut x = [0; L];
        x[(L - 8)..L].copy_from_slice(&nonce.to_be_bytes());
        x
    }

    pub fn client_nonce<const L: usize>(&self) -> [u8; L] {
        let nonce = self.seq_client_nonce.fetch_add(1, Ordering::Relaxed);

        let mut x = [0; L];
        x[(L - 8)..L].copy_from_slice(&nonce.to_be_bytes());
        x
    }

    pub fn encrypt_server(&self, plaintext: &TlsPlaintext) -> Result<TlsCiphertext> {
        let nonce = xor(self.server_nonce(), self.server_handshake_iv);
        TlsCiphertext::encrypt(plaintext, self.server_handshake_key, nonce)
    }

    pub fn decrypt_client(&self, ciphertext: &TlsCiphertext) -> Result<TlsPlaintext> {
        let nonce = xor(self.client_nonce(), self.client_handshake_iv);
        let plaintext = ciphertext.decrypt(self.client_handshake_key, nonce)?;
        Ok(plaintext)
    }
}

pub struct TlsApplicationSecureContext<H: Hasher> {
    seq_server_nonce: AtomicU64,
    seq_client_nonce: AtomicU64,

    server_application_traffic: [u8; H_LENGTH],
    server_application_key: [u8; KEY_LENGTH],
    server_application_iv: [u8; IV_LENGTH],

    client_application_traffic: [u8; H_LENGTH],
    client_application_key: [u8; KEY_LENGTH],
    client_application_iv: [u8; IV_LENGTH],

    _hash: PhantomData<H>,
}

impl<H: Hasher> TlsApplicationSecureContext<H> {
    pub fn new(handshake_secret: [u8; H_LENGTH], transcript_hash: [u8; H_LENGTH]) -> Result<Self> {
        let empty_hash = H::hash(&[]);

        let derived_secret =
            hkdf_expand_label::<H, H_LENGTH>(&handshake_secret, "derived", &empty_hash)?;
        let main_secret = hkdf_extract::<H>(&derived_secret, &[0; H_LENGTH]);

        // ## Server
        let server_application_traffic =
            hkdf_expand_label::<H, H_LENGTH>(&main_secret, "s ap traffic", &transcript_hash)?;
        let server_application_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&server_application_traffic, "key", &[])?;
        let server_application_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&server_application_traffic, "iv", &[])?;

        // ## Client
        let client_application_traffic =
            hkdf_expand_label::<H, H_LENGTH>(&main_secret, "c ap traffic", &transcript_hash)?;
        let client_application_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&client_application_traffic, "key", &[])?;
        let client_application_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&client_application_traffic, "iv", &[])?;

        Ok(Self {
            seq_server_nonce: AtomicU64::new(0),
            seq_client_nonce: AtomicU64::new(0),
            server_application_traffic,
            server_application_key,
            server_application_iv,
            client_application_traffic,
            client_application_key,
            client_application_iv,
            _hash: PhantomData,
        })
    }

    pub fn server_nonce<const L: usize>(&self) -> [u8; L] {
        let nonce = self.seq_server_nonce.fetch_add(1, Ordering::Relaxed);

        let mut x = [0; L];
        x[(L - 8)..L].copy_from_slice(&nonce.to_be_bytes());
        x
    }

    pub fn client_nonce<const L: usize>(&self) -> [u8; L] {
        let nonce = self.seq_client_nonce.fetch_add(1, Ordering::Relaxed);

        let mut x = [0; L];
        x[(L - 8)..L].copy_from_slice(&nonce.to_be_bytes());
        x
    }

    pub fn update_keys(&mut self) -> Result<()> {
        // ## Server
        self.server_application_traffic =
            hkdf_expand_label::<H, H_LENGTH>(&self.server_application_traffic, "traffic upd", &[])?;
        self.server_application_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&self.server_application_traffic, "key", &[])?;
        self.server_application_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&self.server_application_traffic, "iv", &[])?;

        // ## Client
        self.client_application_traffic =
            hkdf_expand_label::<H, H_LENGTH>(&self.client_application_traffic, "traffic upd", &[])?;
        self.client_application_key =
            hkdf_expand_label::<H, KEY_LENGTH>(&self.client_application_traffic, "key", &[])?;
        self.client_application_iv =
            hkdf_expand_label::<H, IV_LENGTH>(&self.client_application_traffic, "iv", &[])?;

        Ok(())
    }

    pub fn decrypt_client(&self, ciphertext: &TlsCiphertext) -> Result<TlsPlaintext> {
        let nonce = xor(self.client_nonce(), self.client_application_iv);
        let plaintext = ciphertext.decrypt(self.client_application_key, nonce)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crypt::hash::sha::Sha384;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_handshake() {
        let transcript_hash = hex!(
            "e05f64fcd082bdb0dce473adf669c276
             9f257a1c75a51b7887468b5e0e7a7de4
             f4d34555112077f16e079019d5a845bd"
        );
        let shared_secret = hex!(
            "df4a291baa1eb7cfa6934b29b474baad
             2697e29f1f920dcc77c8a0a088447624"
        );

        let context =
            TlsHandshakeSecureContext::<Sha384>::new(Some(&shared_secret), None, transcript_hash)
                .unwrap();

        assert_eq!(
            context.handshake_secret,
            hex!(
                "bdbbe8757494bef20de932598294ea65
                 b5e6bf6dc5c02a960a2de2eaa9b07c92
                 9078d2caa0936231c38d1725f179d299"
            )
        );
        assert_eq!(
            context.server_handshake_secret,
            hex!(
                "23323da031634b241dd37d61032b62a4
                 f450584d1f7f47983ba2f7cc0cdcc39a
                 68f481f2b019f9403a3051908a5d1622"
            )
        );
        assert_eq!(
            context.server_handshake_key,
            hex!(
                "9f13575ce3f8cfc1df64a77ceaffe897
                 00b492ad31b4fab01c4792be1b266b7f"
            )
        );
        assert_eq!(
            context.server_handshake_iv,
            hex!("9563bc8b590f671f488d2da3")
        );
        assert_eq!(
            context.client_handshake_secret,
            hex!(
                "db89d2d6df0e84fed74a2288f8fd4d09
                 59f790ff23946cdf4c26d85e51bebd42
                 ae184501972f8d30c4a3e4a3693d0ef0"
            )
        );
        assert_eq!(
            context.client_handshake_key,
            hex!(
                "1135b4826a9a70257e5a391ad93093df
                 d7c4214812f493b3e3daae1eb2b1ac69"
            )
        );
        assert_eq!(
            context.client_handshake_iv,
            hex!("4256d2e0e88babdd05eb2f27")
        );
    }

    #[test]
    fn test_application() {
        let transcript_hash = hex!(
            "fa6800169a6baac19159524fa7b9721b
             41be3c9db6f3f93fa5ff7e3db3ece204
             d2b456c51046e40ec5312c55a86126f5"
        );
        let handshake_secret = hex!(
            "bdbbe8757494bef20de932598294ea65
             b5e6bf6dc5c02a960a2de2eaa9b07c92
             9078d2caa0936231c38d1725f179d299"
        );

        let context =
            TlsApplicationSecureContext::<Sha384>::new(handshake_secret, transcript_hash).unwrap();

        assert_eq!(
            context.server_application_key,
            hex!(
                "01f78623f17e3edcc09e944027ba3218
                 d57c8e0db93cd3ac419309274700ac27"
            )
        );
        assert_eq!(
            context.server_application_iv,
            hex!("196a750b0c5049c0cc51a541")
        );
        assert_eq!(
            context.client_application_key,
            hex!(
                "de2f4c7672723a692319873e5c227606
                 691a32d1c59d8b9f51dbb9352e9ca9cc"
            )
        );
        assert_eq!(
            context.client_application_iv,
            hex!("bb007956f474b25de902432f")
        );
    }
}
