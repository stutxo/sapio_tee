//! Deterministic, attested KMS provisioning of the Sapio BIP32 root.
//!
//! Derivation v1 (all literal strings below are ASCII, without a terminator):
//! 1. Let `h` be the blockhash's 32 consensus/internal-order bytes, i.e. the
//!    reverse of its usual displayed hexadecimal representation.
//! 2. Starting with counter zero, hash `"sapio-tee/p256-nums/v1" || h ||
//!    u32be(counter)`. Interpret `0x02 || digest` as a compressed P-256 point;
//!    retry the next counter if decompression fails. This fixes even y and does
//!    not construct a point by multiplying a known scalar by the generator.
//! 3. Send the point's SPKI DER encoding to KMS DeriveSharedSecret with ECDH.
//! 4. HKDF-SHA256 uses the 32-byte shared secret as IKM, the salt
//!    `"sapio-tee/root-extract/v1"`, and info `"sapio-tee/bip32-root/v1" ||
//!    u32be(key_id.len()) || key_id UTF-8 || h || network_tag`. Network tags are
//!    bitcoin=0, testnet=1, testnet4=2, signet=3, regtest=4.
//! 5. Expand to 64 bytes and use those bytes as the BIP32 master seed.
//!
//! These encodings are a persistent key identity: changing them changes roots.
//! A multi-region key's replicas have different ARNs and thus different roots.
//! A nonzero blockhash alone does not establish provenance or freshness. The
//! operator must fix the restrictive KMS policy before the chosen blockhash is
//! predictable, and clients must independently verify that chronology.

use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use aws_sdk_kms::{
    config::{retry::RetryConfig, timeout::TimeoutConfig, Credentials, Region},
    primitives::Blob,
    types::KeyAgreementAlgorithmSpec,
    Client,
};
use bitcoin::{bip32::Xpriv, hashes::Hash, BlockHash, Network};
use hkdf::Hkdf;
use p256::{pkcs8::EncodePublicKey, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KMS_PROXY_ENDPOINT: &str = "http://127.0.0.1:9999";
const NUMS_DOMAIN: &[u8] = b"sapio-tee/p256-nums/v1";
const HKDF_SALT: &[u8] = b"sapio-tee/root-extract/v1";
const ROOT_INFO_DOMAIN: &[u8] = b"sapio-tee/bip32-root/v1";

/// Immutable public inputs identifying a signer. All fields must be supplied.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Canonical full KMS key ARN; aliases and bare key IDs are not accepted.
    pub key_id: String,
    pub blockhash: BlockHash,
    /// Explicit Bitcoin chain selection, including mainnet if requested.
    pub network: Network,
}

impl Settings {
    /// Reject unsupported partitions/regions, incomplete key ARNs and zero hashes.
    /// The typed, required `network` field admits exactly Bitcoin's named networks.
    pub fn validate(&self) -> Result<()> {
        key_region(&self.key_id)?;
        ensure!(
            self.blockhash != BlockHash::all_zeros(),
            "blockhash must be nonzero"
        );
        Ok(())
    }
}

/// Derive a root only through the measured, enclave-local attesting KMS proxy.
///
/// The caller must retain this root inside the enclave. There is deliberately no
/// endpoint override, credential chain, host seed import, or failure fallback.
/// The KMS key must be ECC_NIST_P256 with KEY_AGREEMENT usage; KMS rejects other
/// curves/usages when given this P-256 SPKI key.
pub async fn derive_root(settings: &Settings) -> Result<Xpriv> {
    settings.validate()?;
    let region = key_region(&settings.key_id)?;
    let public_key = nums_point(&settings.blockhash)?
        .to_public_key_der()
        .context("encoding the P-256 NUMS point as SPKI DER")?;

    // These are deliberately non-secret placeholders, not fallback credentials.
    // The pinned enclave-local proxy extracts the SigV4 region, inserts Recipient
    // attestation, re-signs with instance credentials and decrypts the recipient
    // ciphertext inside the enclave. No ambient SDK config is loaded here.
    let config = aws_sdk_kms::Config::builder()
        .behavior_version_latest()
        .region(Region::new(region.to_owned()))
        .credentials_provider(Credentials::new(
            "ENCLAVE_PROXY_ONLY",
            "ENCLAVE_PROXY_ONLY",
            None,
            None,
            "measured-enclave-kms-proxy",
        ))
        .endpoint_url(KMS_PROXY_ENDPOINT)
        .retry_config(RetryConfig::standard().with_max_attempts(3))
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(3))
                .read_timeout(Duration::from_secs(15))
                .operation_attempt_timeout(Duration::from_secs(20))
                .operation_timeout(Duration::from_secs(45))
                .build(),
        )
        .build();

    let mut output = Client::from_conf(config)
        .derive_shared_secret()
        .key_id(&settings.key_id)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(public_key.as_bytes()))
        .send()
        .await
        // SDK errors can retain a raw response body. Do not propagate that body
        // into API responses or logging, even on a malformed secret response.
        .map_err(|_| anyhow!("KMS DeriveSharedSecret failed through the enclave proxy"))?;

    // Take ownership before checking metadata so even a rejected response's
    // plaintext is wiped. Never clone, format or log the SDK response/secret.
    let secret = Zeroizing::new(
        output
            .shared_secret
            .take()
            .context("KMS proxy returned no shared secret")?
            .into_inner(),
    );
    ensure!(
        output.key_id.as_deref() == Some(settings.key_id.as_str()),
        "KMS response key ARN did not match the requested key"
    );
    ensure!(
        output.key_agreement_algorithm == Some(KeyAgreementAlgorithmSpec::Ecdh),
        "KMS response did not use ECDH"
    );
    ensure!(
        output.ciphertext_for_recipient.is_none(),
        "KMS recipient ciphertext was not consumed by the enclave proxy"
    );
    root_from_secret(settings, secret.as_slice())
}

fn key_region(key_id: &str) -> Result<&str> {
    let mut fields = key_id.split(':');
    ensure!(
        fields.next() == Some("arn")
            && fields.next() == Some("aws")
            && fields.next() == Some("kms"),
        "key_id must be a full arn:aws:kms key ARN"
    );
    let region = fields.next().context("KMS key ARN is missing its region")?;
    // Standard commercial partition KMS regions. A future region must be added
    // in measured code, not supplied as an arbitrary signing-scope/host string.
    // https://docs.aws.amazon.com/general/latest/gr/kms.html
    ensure!(
        matches!(
            region,
            "af-south-1"
                | "ap-east-1"
                | "ap-east-2"
                | "ap-northeast-1"
                | "ap-northeast-2"
                | "ap-northeast-3"
                | "ap-south-1"
                | "ap-south-2"
                | "ap-southeast-1"
                | "ap-southeast-2"
                | "ap-southeast-3"
                | "ap-southeast-4"
                | "ap-southeast-5"
                | "ap-southeast-6"
                | "ap-southeast-7"
                | "ca-central-1"
                | "ca-west-1"
                | "eu-central-1"
                | "eu-central-2"
                | "eu-north-1"
                | "eu-south-1"
                | "eu-south-2"
                | "eu-west-1"
                | "eu-west-2"
                | "eu-west-3"
                | "il-central-1"
                | "me-central-1"
                | "me-south-1"
                | "mx-central-1"
                | "sa-east-1"
                | "us-east-1"
                | "us-east-2"
                | "us-west-1"
                | "us-west-2"
        ),
        "KMS key ARN uses an unsupported AWS region"
    );
    let account = fields
        .next()
        .context("KMS key ARN is missing its account")?;
    ensure!(
        account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()),
        "KMS key ARN must contain a 12-digit AWS account"
    );
    let resource = fields.next().context("KMS key ARN is missing its key")?;
    ensure!(fields.next().is_none(), "KMS key ARN has extra components");
    let key = resource
        .strip_prefix("key/")
        .context("KMS key ARN must identify a key, not an alias")?;
    let lowercase_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let valid_key = if let Some(id) = key.strip_prefix("mrk-") {
        id.len() == 32 && id.bytes().all(lowercase_hex)
    } else {
        key.len() == 36
            && key.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    lowercase_hex(b)
                }
            })
    };
    ensure!(
        valid_key,
        "KMS key ARN must contain a canonical lowercase UUID or mrk- key ID"
    );
    Ok(region)
}

fn nums_point(blockhash: &BlockHash) -> Result<PublicKey> {
    let mut prefix = Sha256::new();
    prefix.update(NUMS_DOMAIN);
    prefix.update(blockhash.as_byte_array());
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    for counter in 0u32..=u32::MAX {
        let mut hash = prefix.clone();
        hash.update(counter.to_be_bytes());
        compressed[1..].copy_from_slice(&hash.finalize());
        if let Ok(point) = PublicKey::from_sec1_bytes(&compressed) {
            return Ok(point);
        }
    }
    bail!("P-256 NUMS derivation exhausted its counter")
}

fn network_tag(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}

fn root_from_secret(settings: &Settings, secret: &[u8]) -> Result<Xpriv> {
    ensure!(
        secret.len() == 32,
        "KMS shared secret must be exactly 32 bytes"
    );
    let arn_length = u32::try_from(settings.key_id.len()).context("KMS key ARN is too long")?;
    let mut seed = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), secret)
        .expand_multi_info(
            &[
                ROOT_INFO_DOMAIN,
                &arn_length.to_be_bytes(),
                settings.key_id.as_bytes(),
                settings.blockhash.as_byte_array(),
                &[network_tag(settings.network)],
            ],
            seed.as_mut(),
        )
        .map_err(|_| anyhow!("HKDF could not produce the BIP32 seed"))?;
    Xpriv::new_master(settings.network, seed.as_ref()).context("deriving the BIP32 master root")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{bip32::Xpub, hex::FromHex, secp256k1::Secp256k1};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    fn settings() -> Settings {
        Settings {
            key_id: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc"
                .to_owned(),
            blockhash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse()
                .unwrap(),
            network: Network::Bitcoin,
        }
    }

    #[test]
    fn nums_retry_vector() {
        // Independently calculated using the P-256 curve equation: counter 0's
        // x has no square root; counter 1 is the first valid even-y point.
        let point = nums_point(&BlockHash::from_byte_array([1; 32])).unwrap();
        let expected = <[u8; 33]>::from_hex(
            "0214eda59eccad5da43a585f25b0b89e6980ec928d6937440e81142b1f9390cd7f",
        )
        .unwrap();
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected);
    }

    #[test]
    fn root_derivation_compatibility_vector() {
        // Independent RFC5869 + BIP32 calculation. This protects persisted key
        // identity, including displayed/internal blockhash byte order.
        let root = root_from_secret(&settings(), &[0x42; 32]).unwrap();
        let xpub = Xpub::from_priv(&Secp256k1::new(), &root);
        assert_eq!(
            xpub.to_string(),
            "xpub661MyMwAqRbcGdaV9bUyRojh6NsyB9n2xoYX3i1oN4iQCsyBdbSjyrmacAjSkfMBxxEpKSdNRNkVdVhwLgDDbnDokrfzRp1BHBoEfqHnZCM"
        );
    }

    #[test]
    fn every_setting_separates_key_material() {
        let original = settings();
        let root = root_from_secret(&original, &[0x42; 32]).unwrap();
        let mut changed_key = original.clone();
        changed_key.key_id = changed_key.key_id.replace("us-east-1", "us-west-2");
        let mut changed_hash = original.clone();
        changed_hash.blockhash = BlockHash::from_byte_array([1; 32]);
        let mut changed_network = original.clone();
        // Test networks share BIP32 version bytes, so compare actual public keys
        // rather than merely comparing xpub/tpub encodings.
        changed_network.network = Network::Testnet;
        let mut changed_network_again = changed_network.clone();
        changed_network_again.network = Network::Signet;
        let secp = Secp256k1::new();
        let original_public = Xpub::from_priv(&secp, &root).public_key;
        for changed in [&changed_key, &changed_hash, &changed_network] {
            let derived = root_from_secret(changed, &[0x42; 32]).unwrap();
            assert_ne!(Xpub::from_priv(&secp, &derived).public_key, original_public);
        }
        let testnet = root_from_secret(&changed_network, &[0x42; 32]).unwrap();
        let signet = root_from_secret(&changed_network_again, &[0x42; 32]).unwrap();
        assert_ne!(
            Xpub::from_priv(&secp, &testnet).public_key,
            Xpub::from_priv(&secp, &signet).public_key
        );
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_key_identifiers() {
        let valid = settings();
        valid.validate().unwrap();
        for invalid in [
            valid.key_id.replace("arn:aws:", "arn:aws-cn:"),
            valid.key_id.replace("us-east-1", "us-gov-west-1"),
            valid.key_id.replace("us-east-1", "us-east-99"),
            valid.key_id.replace("123456789012:", "1234:"),
            valid.key_id.replace("key/", "alias/"),
            valid.key_id.replace("key/", "key/extra/"),
            valid.key_id.replace("789abc", "789ABC"),
            format!("{}:extra", valid.key_id),
            "alias/sapio".to_owned(),
            "12345678-1234-1234-1234-123456789abc".to_owned(),
        ] {
            let mut rejected = valid.clone();
            rejected.key_id = invalid;
            assert!(rejected.validate().is_err(), "{}", rejected.key_id);
        }
        let mut zero_hash = valid;
        zero_hash.blockhash = BlockHash::all_zeros();
        assert!(zero_hash.validate().is_err());
    }
}
