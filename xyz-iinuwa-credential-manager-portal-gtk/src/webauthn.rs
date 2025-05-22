use std::{collections::HashMap, time::Duration};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use libwebauthn::{
    ops::webauthn::{CredentialProtectionPolicy, MakeCredentialLargeBlobExtension},
    proto::ctap2::{
        Ctap2AttestationStatement, Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor,
        Ctap2PublicKeyCredentialType, Ctap2Transport,
    },
};
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use zbus::zvariant::{DeserializeDict, Type};

use crate::cose::{CoseKeyAlgorithmIdentifier, CoseKeyType};

#[derive(Debug)]
pub enum Error {
    Unknown,
    NotSupported,
    InvalidState,
    NotAllowed,
    Constraint,
    Internal(String),
}

pub(crate) fn create_attestation_object(
    authenticator_data: &[u8],
    attestation_statement: &AttestationStatement,
    _enterprise_attestation_possible: bool,
) -> Result<Vec<u8>, Error> {
    let mut attestation_object = Vec::new();
    let mut cbor_writer = crate::cbor::CborWriter::new(&mut attestation_object);
    cbor_writer.write_map_start(3).unwrap();
    cbor_writer.write_text("fmt").unwrap();
    match attestation_statement {
        AttestationStatement::Packed {
            algorithm,
            signature,
            certificates,
        } => {
            cbor_writer.write_text("packed").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            let len = if certificates.is_empty() { 2 } else { 3 };
            cbor_writer.write_map_start(len).unwrap();
            cbor_writer.write_text("alg").unwrap();
            cbor_writer.write_number((*algorithm).into()).unwrap();
            cbor_writer.write_text("sig").unwrap();
            cbor_writer.write_bytes(signature).unwrap();
            if !certificates.is_empty() {
                cbor_writer.write_text("x5c").unwrap();
                cbor_writer.write_array_start(certificates.len()).unwrap();
                for cert in certificates.iter() {
                    cbor_writer.write_bytes(cert).unwrap();
                }
            }
        }
        AttestationStatement::None => {
            cbor_writer.write_text("none").unwrap();
            cbor_writer.write_text("attStmt").unwrap();
            cbor_writer.write_map_start(0).unwrap();
        }
    };

    cbor_writer.write_text("authData").unwrap();
    cbor_writer.write_bytes(authenticator_data).unwrap();

    Ok(attestation_object)
}

/*
#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct ClientData {
    client_data_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    token_binding: Option<TokenBinding>,
}

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct TokenBinding {
    status: String,
    id: Option<String>,
}
*/

#[derive(DeserializeDict, Type)]
#[zvariant(signature = "dict")]
pub(crate) struct AssertionOptions {
    user_verification: Option<bool>,
    user_presence: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MakeCredentialOptions {
    /// Timeout in milliseconds
    #[serde(deserialize_with = "crate::serde::duration::from_opt_ms")]
    #[serde(default)]
    pub timeout: Option<Duration>,
    #[serde(rename = "excludedCredentials")]
    pub excluded_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// https://www.w3.org/TR/webauthn-3/#enum-attestation-convey
    pub attestation: Option<String>,
    /// extensions input as a JSON object
    pub extensions: Option<MakeCredentialExtensions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MakeCredentialExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_protection_policy: Option<CredentialProtectionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce_credential_protection_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Prf>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct LargeBlobExtension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support: Option<MakeCredentialLargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Prf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) eval: Option<PRFValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) eval_by_credential: Option<HashMap<String, PRFValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PRFValue {
    // base64 encoded data
    pub first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

impl PRFValue {
    pub(crate) fn decode(&self) -> libwebauthn::ops::webauthn::PRFValue {
        let mut res = libwebauthn::ops::webauthn::PRFValue::default();
        let first = URL_SAFE_NO_PAD.decode(&self.first).unwrap();
        let len_to_copy = std::cmp::min(first.len(), 32); // Determine how many bytes to copy
        res.first[..len_to_copy].copy_from_slice(&first[..len_to_copy]);
        if let Some(second) = self
            .second
            .as_ref()
            .map(|second| URL_SAFE_NO_PAD.decode(second).unwrap())
        {
            let len_to_copy = std::cmp::min(second.len(), 32); // Determine how many bytes to copy
            let mut res_second = [0u8; 32];
            res_second[..len_to_copy].copy_from_slice(&second[..len_to_copy]);
            res.second = Some(res_second);
        }
        res
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GetCredentialOptions {
    /// Challenge bytes in base64url-encoding with no padding.
    pub(crate) challenge: String,

    #[serde(deserialize_with = "crate::serde::duration::from_opt_ms")]
    #[serde(default)]
    pub(crate) timeout: Option<Duration>,

    /// Relying Party ID.
    /// If not set, the request origin's effective domain will be used instead.
    #[serde(rename = "rpId")]
    pub(crate) rp_id: Option<String>,

    /// An list of allowed credentials, in descending order of RP preference.
    /// If empty, then any credential that can fulfill the request is allowed.
    #[serde(rename = "allowCredentials")]
    #[serde(default)]
    pub(crate) allow_credentials: Vec<CredentialDescriptor>,

    /// Defaults to `preferred`
    #[serde(rename = "userVerification")]
    pub(crate) user_verification: Option<String>,

    /// Contextual information from the RP to help the client guide the user
    /// through the authentication ceremony.
    #[serde(default)]
    pub(crate) hints: Vec<String>,

    pub(crate) extensions: Option<GetCredentialExtensions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetCredentialExtensions {
    // TODO: appid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_cred_blob: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<LargeBlobExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Prf>,
}

#[derive(Debug, Deserialize, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor
pub(crate) struct CredentialDescriptor {
    /// Type of the public key credential the caller is referring to.
    ///
    /// The value SHOULD be a member of PublicKeyCredentialType but client
    /// platforms MUST ignore any PublicKeyCredentialDescriptor with an unknown
    /// type.
    #[serde(rename = "type")]
    pub(crate) cred_type: String,
    /// Credential ID of the public key credential the caller is referring to.
    #[serde(with = "crate::serde::b64")]
    pub(crate) id: Vec<u8>,
    pub(crate) transports: Option<Vec<String>>,
}

impl TryFrom<&CredentialDescriptor> for Ctap2PublicKeyCredentialDescriptor {
    type Error = Error;
    fn try_from(value: &CredentialDescriptor) -> Result<Self, Self::Error> {
        let transports = value.transports.as_ref().filter(|t| !t.is_empty());
        let transports = match transports {
            Some(transports) => {
                let mut transport_list = transports.iter().map(|t| match t.as_ref() {
                    "ble" => Some(Ctap2Transport::BLE),
                    "nfc" => Some(Ctap2Transport::NFC),
                    "usb" => Some(Ctap2Transport::USB),
                    "internal" => Some(Ctap2Transport::INTERNAL),
                    _ => None,
                });
                if transport_list.any(|t| t.is_none()) {
                    return Err(Error::Internal(
                        "Invalid transport type specified".to_owned(),
                    ));
                }
                transport_list.collect()
            }
            None => None,
        };
        Ok(Self {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: value.id.clone().into(),
            transports,
        })
    }
}
impl TryFrom<CredentialDescriptor> for Ctap2PublicKeyCredentialDescriptor {
    type Error = Error;
    fn try_from(value: CredentialDescriptor) -> Result<Self, Self::Error> {
        Ctap2PublicKeyCredentialDescriptor::try_from(&value)
    }
}

#[derive(Debug, DeserializeDict, Type)]
#[zvariant(signature = "dict")]
/// https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection
pub(crate) struct AuthenticatorSelectionCriteria {
    /// https://www.w3.org/TR/webauthn-3/#enum-attachment
    #[zvariant(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,

    /// https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    #[zvariant(rename = "residentKey")]
    pub resident_key: Option<String>,

    // Implied by resident_key == "required", deprecated in webauthn
    // https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement
    // #[zvariant(rename = "requireResidentKey")]
    // require_resident_key: Option<bool>,
    /// https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement
    #[zvariant(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Clone, Deserialize)]
/// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
pub(crate) struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

impl PublicKeyCredentialParameters {
    pub(crate) fn new(alg: i64) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg,
        }
    }
}

impl TryFrom<&PublicKeyCredentialParameters> for Ctap2CredentialType {
    type Error = Error;

    fn try_from(value: &PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        let algorithm = match value.alg {
            -7 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::ES256,
            -8 => libwebauthn::proto::ctap2::Ctap2COSEAlgorithmIdentifier::EDDSA,
            // TODO: we should still pass on the raw value to the authenticator and let it decide whether it's supported.
            _ => {
                return Err(Error::Internal(
                    "Invalid algorithm passed for new credential".to_owned(),
                ))
            }
        };
        Ok(Self {
            public_key_type: Ctap2PublicKeyCredentialType::PublicKey,
            algorithm,
        })
    }
}

impl TryFrom<&PublicKeyCredentialParameters> for CoseKeyType {
    type Error = String;
    fn try_from(value: &PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        match value.alg {
            -7 => Ok(CoseKeyType::ES256_P256),
            -8 => Ok(CoseKeyType::EDDSA_ED25519),
            -257 => Ok(CoseKeyType::RS256),
            _ => Err("Invalid or unsupported algorithm specified".to_owned()),
        }
    }
}

impl TryFrom<PublicKeyCredentialParameters> for CoseKeyType {
    type Error = String;
    fn try_from(value: PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        CoseKeyType::try_from(&value)
    }
}

#[derive(Clone)]
pub struct CredentialSource {
    pub cred_type: PublicKeyCredentialType,

    /// A probabilistically-unique byte sequence identifying a public key
    /// credential source and its authentication assertions.
    pub id: Vec<u8>,

    /// The credential private key
    pub private_key: Vec<u8>,

    pub key_parameters: PublicKeyCredentialParameters,

    /// The Relying Party Identifier, for the Relying Party this public key
    /// credential source is scoped to.
    pub rp_id: String,

    /// The user handle is specified by a Relying Party, as the value of
    /// `user.id`, and used to map a specific public key credential to a specific
    /// user account with the Relying Party. Authenticators in turn map RP IDs
    /// and user handle pairs to public key credential sources.
    ///
    /// A user handle is an opaque byte sequence with a maximum size of 64
    /// bytes, and is not meant to be displayed to the user.
    pub user_handle: Option<Vec<u8>>,

    // Any other information the authenticator chooses to include.
    /// other information used by the authenticator to inform its UI. For
    /// example, this might include the user’s displayName. otherUI is a
    /// mutable item and SHOULD NOT be bound to the public key credential
    /// source in a way that prevents otherUI from being updated.
    pub other_ui: Option<String>,
}

impl CredentialSource {
    pub(crate) fn rp_id_hash<'a>(&'a self) -> Vec<u8> {
        let hash = digest::digest(&digest::SHA256, self.rp_id.as_bytes());
        hash.as_ref().to_owned()
    }
}

#[derive(Clone)]
pub(crate) enum PublicKeyCredentialType {
    PublicKey,
}

#[derive(Debug, PartialEq)]
pub(crate) enum AttestationStatementFormat {
    None,
    Packed,
}

#[derive(Debug, PartialEq)]
pub(crate) enum AttestationStatement {
    None,
    Packed {
        algorithm: CoseKeyAlgorithmIdentifier,
        signature: Vec<u8>,
        certificates: Vec<Vec<u8>>,
    },
}

impl TryFrom<&Ctap2AttestationStatement> for AttestationStatement {
    type Error = Error;

    fn try_from(value: &Ctap2AttestationStatement) -> Result<Self, Self::Error> {
        match value {
            Ctap2AttestationStatement::None(_) => Ok(AttestationStatement::None),
            Ctap2AttestationStatement::PackedOrAndroid(att_stmt) => {
                let alg = att_stmt
                    .algorithm
                    .try_into()
                    .map_err(|_| Error::NotSupported)?;
                Ok(Self::Packed {
                    algorithm: alg,
                    signature: att_stmt.signature.as_ref().to_vec(),
                    certificates: att_stmt
                        .certificates
                        .iter()
                        .map(|c| c.as_ref().to_vec())
                        .collect(),
                })
            }
            _ => {
                debug!("Unsupported attestation type: {:?}", value);
                return Err(Error::NotSupported);
            }
        }
    }
}

pub struct CreatePublicKeyCredentialResponse {
    cred_type: String,

    /// Raw bytes of credential ID.
    raw_id: Vec<u8>,

    response: AttestationResponse,

    /// JSON string of extension output
    extensions: String,

    /// If the device used is builtin ("platform") or removable ("cross-platform", aka "roaming")
    attachment_modality: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPropertiesOutput {
    /// This OPTIONAL property, known abstractly as the resident key credential property (i.e., client-side discoverable credential property), is a Boolean value indicating whether the PublicKeyCredential returned as a result of a registration ceremony is a client-side discoverable credential. If rk is true, the credential is a discoverable credential. if rk is false, the credential is a server-side credential. If rk is not present, it is not known whether the credential is a discoverable credential or a server-side credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsLargeBlobOutputs {
    /// true if, and only if, the created credential supports storing large blobs. Only present in registration outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported: Option<bool>,
    /// The opaque byte string that was associated with the credential identified by rawId. Only valid if read was true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<Vec<u8>>,
    /// A boolean that indicates that the contents of write were successfully stored on the authenticator, associated with the specified credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsPRFValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsPRFOutputs {
    /// true if, and only if, the one or two PRFs are available for use with the created credential. This is only reported during registration and is not present in the case of authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// The results of evaluating the PRF for the inputs given in eval or evalByCredential. Outputs may not be available during registration; see comments in eval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<AuthenticationExtensionsPRFValues>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicKeyExtensionsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropertiesOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<AuthenticationExtensionsLargeBlobOutputs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<AuthenticationExtensionsPRFOutputs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
}

/// Returned from a creation of a new public key credential.
pub struct AttestationResponse {
    /// clientDataJSON.
    client_data_json: String,

    /// Bytes containing authenticator data and an attestation statement.
    attestation_object: Vec<u8>,

    /// Transports that the authenticator is believed to support, or an
    /// empty sequence if the information is unavailable.
    ///
    /// Should be one of
    /// - `usb`
    /// - `nfc`
    /// - `ble`
    /// - `internal`
    ///
    /// but others may be specified.
    transports: Vec<String>,

    /// Encodes contextual bindings made by the authenticator. These bindings
    /// are controlled by the authenticator itself.
    authenticator_data: Vec<u8>,
}

impl CreatePublicKeyCredentialResponse {
    pub fn new(
        id: Vec<u8>,
        attestation_object: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: String,
        transports: Option<Vec<String>>,
        extension_output_json: String,
        attachment_modality: String,
    ) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            raw_id: id,
            response: AttestationResponse {
                client_data_json,
                attestation_object,
                transports: transports.unwrap_or_default(),
                authenticator_data,
            },
            extensions: extension_output_json,
            attachment_modality,
        }
    }

    pub fn get_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.raw_id)
    }

    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": URL_SAFE_NO_PAD.encode(self.response.client_data_json.as_bytes()),
            "attestationObject": URL_SAFE_NO_PAD.encode(&self.response.attestation_object),
            "transports": self.response.transports,
        });
        let extensions: serde_json::Value = serde_json::from_str(&self.extensions)
            .expect("Extensions json to be formatted properly");
        let output = json!({
            "id": self.get_id(),
            "rawId": self.get_id(),
            "response": response,
            "authenticatorAttachment": self.attachment_modality,
            "clientExtensionResults": extensions,
        });
        output.to_string()
    }
}

pub struct GetPublicKeyCredentialResponse {
    pub(crate) cred_type: String,

    /// clientDataJSON.
    pub(crate) client_data_json: String,

    /// Raw bytes of credential ID. Not returned if only one descriptor was
    /// passed in the allow credentials list.
    pub(crate) raw_id: Option<Vec<u8>>,

    /// Encodes contextual bindings made by the authenticator. These bindings
    /// are controlled by the authenticator itself.
    pub(crate) authenticator_data: Vec<u8>,

    pub(crate) signature: Vec<u8>,

    /// The user handle associated when this public key credential source was
    /// created. This item is nullable, however user handle MUST always be
    /// populated for discoverable credentials.
    pub(crate) user_handle: Option<Vec<u8>>,

    /// Whether the used device is "cross-platform" (aka "roaming", i.e.: can be
    /// removed from the platform) or is built-in ("platform").
    pub(crate) attachment_modality: String,

    /// Unsigned extension output
    /// Unlike CreatePublicKey, we can't use a directly serialized JSON string here,
    /// because we have to encode/decode the byte arrays for the JavaScript-communication
    pub(crate) extensions: Option<GetPublicKeyCredentialUnsignedExtensionsResponse>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyCredentialHMACGetSecretOutput {
    // base64-encoded bytestring
    pub output1: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub output2: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct GetPublicKeyCredentialLargeBlobOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub blob: Option<String>,
    // Not yet supported
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub written: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialPrfOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<GetPublicKeyCredentialPRFValue>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialPRFValue {
    // base64-encoded bytestring
    pub first: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    // base64-encoded bytestring
    pub second: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct GetPublicKeyCredentialUnsignedExtensionsResponse {
    pub hmac_get_secret: Option<GetPublicKeyCredentialHMACGetSecretOutput>,
    pub large_blob: Option<GetPublicKeyCredentialLargeBlobOutput>,
    pub prf: Option<GetPublicKeyCredentialPrfOutput>,
}

// Unlike CreatePublicKey, for GetPublicKey, we have a lot of Byte arrays,
// so we need a lot of de/constructions, instead of serializing it directly
impl From<&libwebauthn::ops::webauthn::GetAssertionResponseUnsignedExtensions>
    for GetPublicKeyCredentialUnsignedExtensionsResponse
{
    fn from(value: &libwebauthn::ops::webauthn::GetAssertionResponseUnsignedExtensions) -> Self {
        Self {
            hmac_get_secret: value.hmac_get_secret.as_ref().map(|x| {
                GetPublicKeyCredentialHMACGetSecretOutput {
                    output1: URL_SAFE_NO_PAD.encode(x.output1),
                    output2: x.output2.map(|output2| URL_SAFE_NO_PAD.encode(output2)),
                }
            }),
            large_blob: value
                .large_blob
                .as_ref()
                .map(|x| GetPublicKeyCredentialLargeBlobOutput {
                    blob: x.blob.as_ref().map(|blob| URL_SAFE_NO_PAD.encode(blob)),
                }),
            prf: value.prf.as_ref().map(|x| GetPublicKeyCredentialPrfOutput {
                results: x
                    .results
                    .as_ref()
                    .map(|results| GetPublicKeyCredentialPRFValue {
                        first: URL_SAFE_NO_PAD.encode(results.first),
                        second: results.second.map(|second| URL_SAFE_NO_PAD.encode(second)),
                    }),
            }),
        }
    }
}

impl GetPublicKeyCredentialResponse {
    pub(crate) fn new(
        client_data_json: String,
        id: Option<Vec<u8>>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<Vec<u8>>,
        attachment_modality: String,
        extensions: Option<GetPublicKeyCredentialUnsignedExtensionsResponse>,
    ) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            client_data_json,
            raw_id: id,
            authenticator_data,
            signature,
            user_handle,
            attachment_modality,
            extensions,
        }
    }
    pub fn to_json(&self) -> String {
        let response = json!({
            "clientDataJSON": URL_SAFE_NO_PAD.encode(self.client_data_json.as_bytes()),
            "authenticatorData": URL_SAFE_NO_PAD.encode(&self.authenticator_data),
            "signature": URL_SAFE_NO_PAD.encode(&self.signature),
            "userHandle": self.user_handle.as_ref().map(|h| URL_SAFE_NO_PAD.encode(h))
        });
        // TODO: I believe this optional since authenticators may omit sending the credential ID if it was
        // unambiguously specified in the request. As a convenience, we should
        // always return a credential ID, even if the authenticator doesn't.
        // This means we'll have to remember the ID on the request if the allow-list has exactly one
        // credential descriptor, then we'll need. This should probably be done in libwebauthn.
        let id = self.raw_id.as_ref().map(|id| URL_SAFE_NO_PAD.encode(id));

        let output = json!({
            "id": id,
            "rawId": id,
            "authenticatorAttachment": self.attachment_modality,
            "response": response,
            "clientExtensionResults": self.extensions,
        });
        output.to_string()
    }
}
