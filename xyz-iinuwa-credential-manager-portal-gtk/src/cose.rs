
use libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier;
use ring::{
    rand::SystemRandom, signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair,
        RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    }
};
use tracing::debug;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(i64)]
pub(super) enum CoseKeyType {
    ES256_P256,
    EDDSA_ED25519,
    RS256,
}

impl CoseKeyType {
    pub fn algorithm(&self) -> CoseKeyAlgorithmIdentifier {
        let params: CoseKeyParameters = (*self).into();
        params.algorithm()
    }
}

impl CoseKeyType {
    pub fn curve(&self) -> Option<CoseEllipticCurveIdentifier> {
        let params: CoseKeyParameters = (*self).into();
        params.curve()
    }
}

pub(super) struct CoseKeyParameters {
    alg: CoseKeyAlgorithmIdentifier,
    crv: Option<CoseEllipticCurveIdentifier>,
}

impl CoseKeyParameters {
    pub fn algorithm(&self) -> CoseKeyAlgorithmIdentifier {
        self.alg
    }

    pub fn curve(&self) -> Option<CoseEllipticCurveIdentifier> {
        self.crv
    }
}

impl From<CoseKeyType> for CoseKeyParameters {
    fn from(value: CoseKeyType) -> Self {
        match value {
            CoseKeyType::ES256_P256 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::ES256, crv: Some(CoseEllipticCurveIdentifier::P256) },
            CoseKeyType::EDDSA_ED25519 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::EdDSA, crv: Some(CoseEllipticCurveIdentifier::Ed25519) },
            CoseKeyType::RS256 => CoseKeyParameters { alg: CoseKeyAlgorithmIdentifier::RS256, crv: None, },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CoseKeyAlgorithmIdentifier {
    ES256,
    EdDSA,
    RS256,
}

impl From<CoseKeyAlgorithmIdentifier> for i64 {
    fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
        match value {
            CoseKeyAlgorithmIdentifier::ES256 => -7,
            CoseKeyAlgorithmIdentifier::EdDSA => -8,
            CoseKeyAlgorithmIdentifier::RS256 => -257,
        }
    }
}

impl From<CoseKeyAlgorithmIdentifier> for i128 {
    fn from(value: CoseKeyAlgorithmIdentifier) -> Self {
        match value {
            CoseKeyAlgorithmIdentifier::ES256 => -7,
            CoseKeyAlgorithmIdentifier::EdDSA => -8,
            CoseKeyAlgorithmIdentifier::RS256 => -257,
        }
    }
}

impl TryFrom<Ctap2COSEAlgorithmIdentifier> for CoseKeyAlgorithmIdentifier {
    type Error = Error;

    fn try_from(value: Ctap2COSEAlgorithmIdentifier) -> Result<Self, Self::Error> {
        match value {
            Ctap2COSEAlgorithmIdentifier::EDDSA => Ok(CoseKeyAlgorithmIdentifier::EdDSA),
            Ctap2COSEAlgorithmIdentifier::ES256 => Ok(CoseKeyAlgorithmIdentifier::ES256),
            Ctap2COSEAlgorithmIdentifier::TOPT => {
                debug!("Unknown public key algorithm type: {:?}", value);
                return Err(Error::Unsupported);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum CoseEllipticCurveIdentifier {
    /// P-256 Elliptic Curve using uncompressed points.
    P256,
    /// P-384 Elliptic Curve using uncompressed points.
    P384,
    /// P-521 Elliptic Curve using uncompressed points.
    P521,
    /// Ed25519 Elliptic Curve using compressed points.
    Ed25519,
}

impl From<CoseEllipticCurveIdentifier> for i64 {
    fn from(value: CoseEllipticCurveIdentifier) -> Self {
        match value {
            CoseEllipticCurveIdentifier::P256 => 1,
            CoseEllipticCurveIdentifier::P384 => 2,
            CoseEllipticCurveIdentifier::P521 => 3,
            CoseEllipticCurveIdentifier::Ed25519 => 6,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidKey,
    Unsupported,
}

pub(super) fn encode_pkcs8_key(
    key_type: CoseKeyType,
    pkcs8_key: &[u8],
) -> Result<Vec<u8>, Error> {
    match key_type {
        CoseKeyType::ES256_P256 => {
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8_key,
                &SystemRandom::new(),
            )
            .unwrap();
            let public_key = key_pair.public_key().as_ref();
            // ring outputs public keys with uncompressed 32-byte x and y coordinates
            if public_key.len() != 65 || public_key[0] != 0x04 {
                return Err(Error::InvalidKey);
            }
            let (x, y) = public_key[1..].split_at(32);
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00101); // map with 5 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): EC2 (2)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): ECDSA-SHA256 (-7)
            cose_key.extend([0b001_00000, 0b000_00001]); // crv (-1): P256 (1)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(x);
            cose_key.extend([0b001_00010, 0b010_11000, 0b0010_0000]); // y (-3): <32-byte string>
            cose_key.extend(y);
            Ok(cose_key)
        }
        CoseKeyType::EDDSA_ED25519 => {
            let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_key).map_err(|_| Error::InvalidKey)?;
            let public_key = key_pair.public_key().as_ref();
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00001]); // kty (1): OKP (1)
            cose_key.extend([0b000_00011, 0b001_00111]); // alg (3): EdDSA (-8)
            cose_key.extend([0b001_00000, 0b000_00110]); // crv (-1): ED25519 (6)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(public_key);
            Ok(cose_key)
        }
        CoseKeyType::RS256 => {
            let key_pair = RsaKeyPair::from_pkcs8(pkcs8_key).map_err(|_| Error::InvalidKey)?;
            let public_key = key_pair.public_key().as_ref();
            // TODO: This is ASN.1 with DER encoding. We could parse this to extract
            // the modulus and exponent properly, but the key length will
            // probably not change, so we're winging it
            // https://stackoverflow.com/a/12750816/11931787
            let n = &public_key[9..(9 + 256)];
            let e = &public_key[public_key.len() - 3..];
            debug_assert_eq!(n.len(), key_pair.public().modulus_len());
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): RSA (3)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): RSASSA-PKCS1-v1_5 using SHA-256 (-257)
            cose_key.extend([0b001_00000, 0b010_11001, 0b0000_0001, 0b0000_0000]); // n (-1): <256-byte string>
            cose_key.extend(n);
            cose_key.extend([0b001_00001, 0b010_00011]); // e (-2): <3-byte string>
            cose_key.extend(e);
            Ok(cose_key)
        }
        _ => todo!(),
    }
}

/// returns CTAP2-serialized public key and algorithm
pub(crate) fn encode_cose_key(public_key: &cosey::PublicKey) -> Result<Vec<u8>, Error> {
    match public_key {
            cosey::PublicKey::P256Key(p256_key) => {
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00101); // map with 5 items
            cose_key.extend([0b000_00001, 0b000_00010]); // kty (1): EC2 (2)
            cose_key.extend([0b000_00011, 0b001_00110]); // alg (3): ECDSA-SHA256 (-7)
            cose_key.extend([0b001_00000, 0b000_00001]); // crv (-1): P256 (1)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(p256_key.x.clone());
            cose_key.extend([0b001_00010, 0b010_11000, 0b0010_0000]); // y (-3): <32-byte string>
            cose_key.extend(p256_key.y.clone());
            Ok(cose_key)
        },
        cosey::PublicKey::Ed25519Key(ed25519_key) => {
            // TODO: Check this
            let mut cose_key: Vec<u8> = Vec::new();
            cose_key.push(0b101_00100); // map with 4 items
            cose_key.extend([0b000_00001, 0b000_00001]); // kty (1): OKP (1)
            cose_key.extend([0b000_00011, 0b001_00111]); // alg (3): EdDSA (-8)
            cose_key.extend([0b001_00000, 0b000_00110]); // crv (-1): ED25519 (6)
            cose_key.extend([0b001_00001, 0b010_11000, 0b0010_0000]); // x (-2): <32-byte string>
            cose_key.extend(ed25519_key.x.clone());
            Ok(cose_key)
        },

        _ => {
            debug!("Cannot serialize unknown key type {:?}", public_key);
            Err(Error::Unsupported)
        }
    }
}
