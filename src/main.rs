use anyhow::{Result, anyhow, bail};
use asn1::{
    DataElement,
    object_identifiers::{rsassaPss, sha256WithRSAEncryption},
    parse_der,
    pkcs1::RsaPrivateKey,
    pkcs8::PrivateKeyInfo,
    x509::{Certificate as X509Certificate, TbsCertificate as X509TbsCertificate},
};
use crypt::{
    elliptic::x25519,
    hash::{
        Hasher,
        sha::{Sha256, Sha384},
    },
    hmac::hmac_hash,
    rsa::{PrivateKey, PublicKey},
};
use tls::{
    cipher_suite::TLS_AES_256_GCM_SHA384,
    error::TlsAlert,
    hkdf::{derive_secret, hkdf_expand_label, hkdf_extract},
    record::{
        TlsCiphertext, TlsContent, TlsPlaintext,
        handshake::{
            Handshake,
            certificate::{Certificate, CertificateEntry},
            certificate_verify::CertificateVerify,
            encrypted_extensions::EncryptedExtensions,
            extension::{KeyShareEntry, NamedGroup, SignatureScheme},
            finished::Finished,
            server_hello::{ServerHello, ServerHelloExtension},
        },
    },
};
use utils::concat_dyn;

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    marker::PhantomData,
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::organized_extensions::OrganizedClientExtensions;

mod organized_extensions;

const VERSION: u16 = 0x0304;

fn load_cert() -> X509TbsCertificate {
    let encoded = fs::read("cert.cer").unwrap();
    let data = parse_der(&encoded);
    X509Certificate::from_data_element(&data)
        .unwrap()
        .tbs_certificate
}

fn load_rsa_keys() -> (PrivateKey, PublicKey) {
    let encoded = std::fs::read("key.der").unwrap();
    let data = parse_der(&encoded);
    let private_key_info = PrivateKeyInfo::from_data_element(&data).unwrap();

    let key_data = parse_der(&private_key_info.private_key.0);
    let rsa_private_key = RsaPrivateKey::from_data_element(&key_data).unwrap();

    (
        PrivateKey {
            modulus: rsa_private_key.modulus.0.clone(),
            exponent: rsa_private_key.private_exponent.0.clone(),
        },
        PublicKey {
            modulus: rsa_private_key.modulus.0.clone(),
            exponent: rsa_private_key.public_exponent.0.clone(),
        },
    )
}

fn xor<const N: usize>(mut a: [u8; N], b: [u8; N]) -> [u8; N] {
    for i in 0..N {
        a[i] ^= b[i];
    }
    a
}

struct ClientHelloInfo {
    legacy_session_id: Box<[u8]>,

    supported_versions: Box<[u16]>,
    // server_name: Option<String>,

    // Cryptography
    key_share: HashMap<NamedGroup, Box<[u8]>>,
    // signature_algorithms: Box<[SignatureScheme]>,
    server_share: Option<KeyShareEntry>,
}

struct TlsSecureContext<H: Hasher> {
    seq_nonce: AtomicU64,

    transcript: Vec<u8>,

    server_handshake_traffic: [u8; 48],
    server_handshake_key: [u8; 32],
    server_handshake_iv: [u8; 12],

    client_handshake_key: [u8; 32],
    client_handshake_iv: [u8; 12],

    _hash: PhantomData<H>,
}

impl<H: Hasher> TlsSecureContext<H> {
    pub fn new(
        key_ecdhe: Option<&[u8]>,
        key_psk: Option<&[u8]>,
        transcript: Vec<u8>,
    ) -> Result<Self> {
        // Key Schedule
        let early_secret = hkdf_extract::<H>(&[0; 48], key_psk.unwrap_or(&[0; 48]));
        let handshake_secret = hkdf_extract::<H>(
            &derive_secret::<H>(&early_secret, "derived", &[]),
            key_ecdhe.unwrap_or(&[0; 32]),
        );

        // Server keys
        let server_handshake_traffic: [u8; 48] =
            derive_secret::<H>(&handshake_secret, "s hs traffic", &transcript)
                .as_ref()
                .try_into()?;
        let server_handshake_key: [u8; 32] =
            hkdf_expand_label::<H>(&server_handshake_traffic, "key", &[], 32)
                .as_ref()
                .try_into()?;
        let server_handshake_iv: [u8; 12] =
            hkdf_expand_label::<H>(&server_handshake_traffic, "iv", &[], 12)
                .as_ref()
                .try_into()?;

        // Client keys
        let client_handshake_traffic_secret: [u8; 48] =
            derive_secret::<H>(&handshake_secret, "c hs traffic", &transcript)
                .as_ref()
                .try_into()?;
        let client_handshake_key: [u8; 32] =
            hkdf_expand_label::<H>(&client_handshake_traffic_secret, "key", &[], 32)
                .as_ref()
                .try_into()?;
        let client_handshake_iv: [u8; 12] =
            hkdf_expand_label::<H>(&client_handshake_traffic_secret, "iv", &[], 12)
                .as_ref()
                .try_into()?;

        // Main
        let main_secret = hkdf_extract::<H>(
            &derive_secret::<H>(&handshake_secret, "derived", &[]),
            &[0; 48],
        );

        Ok(Self {
            seq_nonce: AtomicU64::new(0),
            transcript,
            server_handshake_traffic,
            server_handshake_key,
            server_handshake_iv,
            client_handshake_key,
            client_handshake_iv,
            _hash: PhantomData,
        })
    }

    pub fn nonce(&self) -> u64 {
        self.seq_nonce.fetch_add(1, Ordering::Relaxed)
    }

    pub fn pad_nonce<const L: usize>(&self) -> [u8; L] {
        let mut x = [0; L];
        x[(L - 8)..L].copy_from_slice(&self.nonce().to_be_bytes());
        x
    }

    pub fn extend_transcript(&mut self, value: &[u8]) {
        self.transcript.extend(value);
    }

    pub fn transcript_hash(&self) -> Box<[u8]> {
        H::hash(&self.transcript)
    }

    pub fn encrypt(&mut self, plaintext: &TlsPlaintext) -> Result<TlsCiphertext> {
        self.transcript.extend(&plaintext.to_raw()[5..]);
        let nonce = xor(self.pad_nonce(), self.server_handshake_iv);
        TlsCiphertext::encrypt(plaintext, self.server_handshake_key, nonce)
    }
}

fn server_hello(client_info: ClientHelloInfo) -> Result<Box<[u8]>> {
    let mut sh_extensions = Vec::from([ServerHelloExtension::new_supported_versions(VERSION)]);

    if let Some(share) = client_info.server_share {
        sh_extensions.push(ServerHelloExtension::new_key_share(share)?);
    }

    // if flag_psk {
    //     sh_extensions.push(ServerHelloExtension::new_pre_shared_key(0));
    // }

    let server_hello = Handshake::ServerHello(ServerHello::new(
        &rand::random(),
        &client_info.legacy_session_id,
        TLS_AES_256_GCM_SHA384,
        &sh_extensions,
    ));
    let sh_record = TlsPlaintext::new_handshake(server_hello)?;
    Ok(sh_record.to_raw())
}

fn handshake(conn: &mut TcpStream) -> Result<()> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    let mut transcript = Vec::<u8>::new();

    // ClientHello

    let ch_raw = &buf[..n];
    transcript.extend(&ch_raw[5..]);
    let ch_record = TlsPlaintext::from_raw(ch_raw)?;
    let TlsContent::Handshake(Handshake::ClientHello(client_hello)) = ch_record.fragment else {
        bail!("Not client hello");
    };
    let ch_exts = OrganizedClientExtensions::organize(client_hello.extensions);

    // EC-DHE

    let key_share = ch_exts
        .key_share
        .ok_or(anyhow!("Missing key_share"))?
        .to_hashmap();

    let x25519_public;
    let x25519_shared;

    if let Some(share) = key_share.get(&NamedGroup::x25519) {
        let (public, private) = x25519::get_keypair();

        x25519_public = Some(public);
        x25519_shared = Some(x25519::get_shared_key(private, share.as_ref().try_into()?));
    } else {
        x25519_public = None;
        x25519_shared = None;
    }

    // ServerHello

    let server_share = x25519_public.map(|share| KeyShareEntry::new(NamedGroup::x25519, &share));
    let client_info = ClientHelloInfo {
        legacy_session_id: client_hello.legacy_session_id,
        supported_versions: ch_exts.supported_versions.unwrap().versions,
        // server_name: ch_exts.server_name,
        key_share,
        server_share,
    };

    let sh_raw = server_hello(client_info)?;
    transcript.extend(&sh_raw[5..]);
    conn.write_all(&sh_raw)?;

    let mut context = TlsSecureContext::<Sha384>::new(
        x25519_shared.as_ref().map(|x| x as &[u8]),
        None,
        transcript,
    )?;

    // EncryptedExtensions
    {
        let record = TlsPlaintext::new_handshake(Handshake::EncryptedExtensions(
            EncryptedExtensions::new(&[])?,
        ))?;
        conn.write_all(&context.encrypt(&record)?.to_raw())?;
    }

    // Certificate
    {
        let certificate = fs::read("cert.cer")?;

        let record = TlsPlaintext::new_handshake(Handshake::Certificate(Certificate::new(
            &[],
            &[CertificateEntry::new(&certificate)?],
        )?))?;
        conn.write_all(&context.encrypt(&record)?.to_raw())?;
    }

    // Determine certificate type
    let cert = load_cert();
    let signature_scheme = if cert.signature_algorithm.is(sha256WithRSAEncryption) {
        tracing::info!("Using RSAE");
        SignatureScheme::rsa_pss_rsae_sha256
    } else if cert.signature_algorithm.is(rsassaPss) {
        tracing::info!("Using RSASSA-PSS");
        SignatureScheme::rsa_pss_pss_sha256
    } else {
        unimplemented!();
    };

    // CertificateVerify
    {
        let transcript_hash = context.transcript_hash();
        let sign_context = concat_dyn![
            [0x20].repeat(64),
            b"TLS 1.3, server CertificateVerify",
            [0x00],
            transcript_hash,
        ];
        let (private_key, public_key) = load_rsa_keys();
        let signature = crypt::rsa::rsassa_pss_sign::<Sha256, { Sha256::DIGEST_SIZE }>(
            &private_key,
            &sign_context,
        );

        crypt::rsa::rsassa_pss_verify::<Sha256, { Sha256::DIGEST_SIZE }>(
            &public_key,
            &sign_context,
            &signature,
        )
        .unwrap();

        let record = TlsPlaintext::new_handshake(Handshake::CertificateVerify(
            CertificateVerify::new(signature_scheme, &signature)?,
        ))?;
        conn.write_all(&context.encrypt(&record)?.to_raw())?;
    }

    // Finished
    {
        let finished_key =
            hkdf_expand_label::<Sha384>(&context.server_handshake_traffic, "finished", &[], 48);
        let verify_data = hmac_hash::<Sha384>(&finished_key, &context.transcript_hash());

        let record = TlsPlaintext::new_handshake(Handshake::Finished(Finished { verify_data }))?;
        conn.write_all(&context.encrypt(&record)?.to_raw())?;
    }

    Ok(())
}

fn handle_connection(mut conn: TcpStream) -> Result<()> {
    if let Err(e) = handshake(&mut conn) {
        match e.downcast::<TlsAlert>() {
            Ok(alert) => {
                tracing::warn!("Alert: {alert:?}");
            }
            Err(e) => return Err(e),
        }
    }

    let mut buf = [0; 2800];
    loop {
        let n = conn.read(&mut buf)?;

        if n == 0 {
            continue;
        }

        tracing::info!("Read {n} bytes");
        let record = TlsPlaintext::from_raw(&buf[..n])?;

        tracing::info!(?record);
    }

    // Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("trace").init();

    let listener = TcpListener::bind("0.0.0.0:3001")?;

    for conn in listener.incoming().filter_map(Result::ok) {
        _ = handle_connection(conn)
            .inspect_err(|e| tracing::error!("TLS connection handle error: {e:?}"));
    }

    Ok(())
}
