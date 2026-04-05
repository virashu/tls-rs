use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Result, anyhow, bail};
use asn1::object_identifiers::{RSASSA_PSS, SHA256_WITH_RSA_ENCRYPTION};
use crypt::{
    elliptic::x25519,
    hash::{
        Hasher,
        sha::{Sha256, Sha384},
    },
    hmac::hmac_hash,
};
use utils::concat_dyn;

use crate::{
    TLS_VERSION,
    protocol::{
        cipher_suite::TLS_AES_256_GCM_SHA384,
        error::TlsAlert,
        hkdf::hkdf_expand_label,
        record::{
            TlsCiphertext,
            TlsContent,
            TlsPlaintext,
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
    },
    server::{
        organized_extensions::OrganizedClientExtensions,
        secure_context::{TlsApplicationSecureContext, TlsHandshakeSecureContext, Transcript},
        server::Config,
    },
};

struct ClientHelloInfo {
    legacy_session_id: Box<[u8]>,

    supported_versions: Box<[u16]>,
    // server_name: Option<String>,

    // Cryptography
    key_share: HashMap<NamedGroup, Box<[u8]>>,
    // signature_algorithms: Box<[SignatureScheme]>,
    server_share: Option<KeyShareEntry>,
}

fn server_hello(client_info: ClientHelloInfo) -> Result<TlsPlaintext> {
    let mut sh_extensions = Vec::from([ServerHelloExtension::new_supported_versions(TLS_VERSION)]);

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
    Ok(sh_record)
}

pub fn handshake(
    config: &Config,
    conn: &mut TcpStream,
) -> Result<TlsApplicationSecureContext<Sha384>> {
    let mut buf = [0; 2800];
    let n = conn.read(&mut buf)?;

    let mut transcript = Transcript::<Sha384>::new();

    // ClientHello

    let ch_raw = &buf[..n];
    let ch_record = TlsPlaintext::from_raw(ch_raw)?;
    transcript.extend_raw(&ch_raw[5..]);
    let TlsContent::Handshake(Handshake::ClientHello(client_hello)) = ch_record.fragment else {
        bail!("Not client hello");
    };
    let ch_exts = OrganizedClientExtensions::organize(client_hello.extensions);

    // ECDHE

    let key_share = ch_exts
        .key_share
        .ok_or(anyhow!("Missing key_share"))?
        .to_hashmap();

    let (x25519_public, x25519_shared) = key_share
        .get(&NamedGroup::x25519)
        .map(|share| -> Result<_> {
            let (public, private) = x25519::get_keypair();
            let shared = x25519::get_shared_key(private, share.as_ref().try_into()?);
            Ok((public, shared))
        })
        .transpose()?
        .unzip();

    // ServerHello

    let server_share = x25519_public.map(|share| KeyShareEntry::new(NamedGroup::x25519, &share));
    let client_info = ClientHelloInfo {
        legacy_session_id: client_hello.legacy_session_id,
        supported_versions: ch_exts.supported_versions.unwrap().versions,
        // server_name: ch_exts.server_name,
        key_share,
        server_share,
    };

    let sh_record = server_hello(client_info)?;
    transcript.extend(&sh_record);
    conn.write_all(&sh_record.to_raw())?;

    let context = TlsHandshakeSecureContext::<Sha384>::new(
        x25519_shared.as_ref().map(|x| x.as_slice()),
        None,
        transcript.hash(),
    )?;

    // Server EncryptedExtensions
    {
        let record = TlsPlaintext::new_handshake(Handshake::EncryptedExtensions(
            EncryptedExtensions::new(&[ServerHelloExtension::new_alpn(b"http/1.1")?])?,
        ))?;
        transcript.extend(&record);
        conn.write_all(&context.encrypt_server(&record)?.to_raw())?;
    }

    // Server Certificate
    {
        let certificate = fs::read("cert.cer")?;

        let record = TlsPlaintext::new_handshake(Handshake::Certificate(Certificate::new(
            &[],
            &[CertificateEntry::new(&certificate)?],
        )?))?;
        transcript.extend(&record);
        conn.write_all(&context.encrypt_server(&record)?.to_raw())?;
    }

    // Determine certificate type
    let cert = &config.certificate;
    let signature_scheme = if cert.signature_algorithm.is(SHA256_WITH_RSA_ENCRYPTION) {
        tracing::info!("Using RSAE");
        SignatureScheme::rsa_pss_rsae_sha256
    } else if cert.signature_algorithm.is(RSASSA_PSS) {
        tracing::info!("Using RSASSA-PSS");
        SignatureScheme::rsa_pss_pss_sha256
    } else {
        unimplemented!();
    };

    // Server CertificateVerify
    {
        let transcript_hash = transcript.hash();
        let sign_context = concat_dyn![
            [0x20].repeat(64),
            b"TLS 1.3, server CertificateVerify",
            [0x00],
            transcript_hash,
        ];
        let signature = loop {
            let signature = crypt::rsa::rsassa_pss_sign::<Sha256, { Sha256::DIGEST_SIZE }>(
                &config.private_key,
                &sign_context,
            );

            match crypt::rsa::rsassa_pss_verify::<Sha256, { Sha256::DIGEST_SIZE }>(
                &config.public_key,
                &sign_context,
                &signature,
            ) {
                Ok(()) => break signature,
                Err(e) => tracing::error!("{e}"),
            }
        };

        let record = TlsPlaintext::new_handshake(Handshake::CertificateVerify(
            CertificateVerify::new(signature_scheme, &signature)?,
        ))?;
        transcript.extend(&record);
        conn.write_all(&context.encrypt_server(&record)?.to_raw())?;
    }

    // Server Finished
    {
        let finished_key =
            hkdf_expand_label::<Sha384, 48>(&context.server_handshake_secret, "finished", &[])?;
        let verify_data = hmac_hash::<Sha384>(&finished_key, &transcript.hash());

        let record = TlsPlaintext::new_handshake(Handshake::Finished(Finished { verify_data }))?;
        transcript.extend(&record);
        conn.write_all(&context.encrypt_server(&record)?.to_raw())?;
    }

    let app_context =
        TlsApplicationSecureContext::<Sha384>::new(context.handshake_secret, transcript.hash())?;

    // # Client

    loop {
        let n = conn.read(&mut buf)?;
        let record = TlsPlaintext::from_raw(&buf[..n])?;

        if matches!(record.fragment, TlsContent::ApplicationData(_)) {
            let ciphertext = TlsCiphertext::from_raw(&buf[..n])?;
            let record = context.decrypt_client(&ciphertext)?;

            tracing::trace!(target: "(IN) (ENCRYPTED)", ?record);

            if matches!(
                record.fragment,
                TlsContent::Handshake(Handshake::Finished(_))
            ) {
                break;
            }
        } else {
            tracing::trace!(target: "(IN)", ?record);
        }
    }

    tracing::info!("Handshake: Done");

    Ok(app_context)
}

pub fn handle_connection(config: &Config, mut conn: TcpStream) -> Result<()> {
    let context = match handshake(config, &mut conn) {
        Ok(c) => c,
        Err(e) => match e.downcast::<TlsAlert>() {
            Ok(alert) => {
                tracing::warn!("Alert: {alert:?}");
                return Ok(());
            }
            Err(e) => return Err(e),
        },
    };

    let mut buf = [0; 2800];
    loop {
        let n = conn.read(&mut buf)?;

        if n == 0 {
            continue;
        }

        tracing::info!("Read {n} bytes");

        if let Ok(ciphertext) = TlsCiphertext::from_raw(&buf[..n]) {
            let record = context.decrypt_client(&ciphertext)?;

            if let TlsContent::ApplicationData(data) = record.fragment {
                let st = data.to_string();
                tracing::info!(?st);
            } else {
                tracing::trace!(target: "(IN)", ?record);
            }
        }
    }

    // Ok(())
}
