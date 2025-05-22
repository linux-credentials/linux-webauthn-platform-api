mod store;

use std::collections::HashMap;

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libwebauthn::fido::AuthenticatorDataFlags;
use openssl::{pkey::PKey, rsa::Rsa};
use ring::{
    digest::{self},
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, RsaKeyPair,
        ECDSA_P256_SHA256_ASN1_SIGNING, RSA_PKCS1_SHA256,
    },
};
use serde::Deserialize;

use crate::cose::{encode_pkcs8_key, CoseKeyType};
use crate::webauthn::{
    self, AttestationStatement, AttestationStatementFormat, CreatePublicKeyCredentialResponse,
    CredentialDescriptor, CredentialSource, Error as WebAuthnError, GetPublicKeyCredentialResponse,
    MakeCredentialOptions, PublicKeyCredentialParameters, PublicKeyCredentialType,
};

static P256: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
// static RNG: &Box<dyn SecureRandom> = &Box::new(SystemRandom::new());

const CAN_CREATE_DISCOVERABLE_CREDENTIAL: bool = true;

/*
async fn create_passkey(
    origin: &str,
    is_same_origin: bool,
    request: &CreatePublicKeyCredentialRequest,
) -> fdo::Result<CreatePublicKeyCredentialResponse> {
    let (response, cred_source, user) =
        webauthn::create_credential(origin, &request.request_json, true).map_err(|_| {
            fdo::WebAuthnError::Failed("Failed to create public key credential".to_string())
        })?;

    let mut contents = String::new();
    contents.push_str("type=public-key"); // TODO: Don't hardcode public-key?
    contents.push_str("&id=");
    URL_SAFE_NO_PAD.encode_string(cred_source.id, &mut contents);
    contents.push_str("&key=");
    URL_SAFE_NO_PAD.encode_string(cred_source.private_key, &mut contents);
    contents.push_str("&rp_id=");
    contents.push_str(&cred_source.rp_id);
    if let Some(user_handle) = &cred_source.user_handle {
        contents.push_str("&user_handle=");
        URL_SAFE_NO_PAD.encode_string(user_handle, &mut contents);
    }

    if let Some(other_ui) = cred_source.other_ui {
        contents.push_str("&other_ui=");
        contents.push_str(&other_ui);
    }
    let content_type = "secret/public-key";
    let display_name = "test"; // TODO
    store::store_secret(
        &[origin],
        display_name,
        &user.display_name,
        content_type,
        None,
        contents.as_bytes(),
    )
    .await
    .map_err(|_| fdo::WebAuthnError::Failed("Failed to save passkey to storage".to_string()))?;

    Ok(CreatePublicKeyCredentialResponse {
        registration_response_json: response.to_json(),
    })
}
*/

#[derive(Deserialize)]
pub(crate) struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params
#[derive(Deserialize)]
pub(crate) struct User {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

struct Assertion {}

pub(crate) fn create_attested_credential_data(
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: &[u8],
) -> Result<Vec<u8>, webauthn::Error> {
    let mut attested_credential_data: Vec<u8> = Vec::new();
    if aaguid.len() != 16 {
        return Err(webauthn::Error::Unknown);
    }
    attested_credential_data.extend(aaguid);
    let cred_length: u16 = TryInto::<u16>::try_into(credential_id.len()).unwrap();
    let cred_length_bytes: Vec<u8> = cred_length.to_be_bytes().to_vec();
    attested_credential_data.extend(&cred_length_bytes);
    attested_credential_data.extend(credential_id);
    attested_credential_data.extend(public_key);
    Ok(attested_credential_data)
}

pub(crate) fn create_authenticator_data(
    rp_id_hash: &[u8],
    flags: &AuthenticatorDataFlags,
    signature_counter: u32,
    attested_credential_data: Option<&[u8]>,
    processed_extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut authenticator_data: Vec<u8> = Vec::new();
    authenticator_data.extend(rp_id_hash);

    authenticator_data.push(flags.bits());

    authenticator_data.extend(signature_counter.to_be_bytes());

    if let Some(attested_credential_data) = attested_credential_data {
        authenticator_data.extend(attested_credential_data);
    }

    if let Some(extensions) = processed_extensions {
        authenticator_data.extend(extensions);
    }
    authenticator_data
}

pub(crate) fn create_credential(
    origin: &str,
    options: &str,
    same_origin: bool,
) -> Result<(CreatePublicKeyCredentialResponse, CredentialSource, User), WebAuthnError> {
    let request_value = serde_json::from_str::<serde_json::Value>(options)
        .map_err(|_| WebAuthnError::Internal("Invalid request JSON".to_string()))?;
    let json = request_value
        .as_object()
        .ok_or_else(|| WebAuthnError::Internal("Invalid request JSON".to_string()))?;
    let challenge = json
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| WebAuthnError::Internal("JSON missing `challenge` field".to_string()))?
        .to_owned();
    let rp = json
        .get("rp")
        .and_then(|val| serde_json::from_str::<RelyingParty>(&val.to_string()).ok())
        .ok_or_else(|| WebAuthnError::Internal("JSON missing `rp` field".to_string()))?;
    let user = json
        .get("user")
        .ok_or(WebAuthnError::Internal(
            "JSON missing `user` field".to_string(),
        ))
        .and_then(|val| {
            serde_json::from_str::<User>(&val.to_string()).map_err(|e| {
                let msg = format!("JSON missing `user` field: {e}");
                WebAuthnError::Internal(msg)
            })
        })?;
    let other_options = serde_json::from_str::<MakeCredentialOptions>(&request_value.to_string())
        .map_err(|_| WebAuthnError::Internal("Invalid request JSON".to_string()))?;
    let (require_resident_key, require_user_verification) =
        if let Some(authenticator_selection) = other_options.authenticator_selection {
            let is_authenticator_storage_capable = true;
            let require_resident_key = authenticator_selection.resident_key.map_or_else(
                || false,
                |r| r == "required" || (r == "preferred" && is_authenticator_storage_capable),
            ); // fallback to authenticator_selection.require_resident_key == true for WebAuthn Level 1?

            let authenticator_can_verify_users = true;
            let require_user_verification = authenticator_selection.user_verification.map_or_else(
                || false,
                |r| r == "required" || (r == "preferred" && authenticator_can_verify_users),
            );

            (require_resident_key, require_user_verification)
        } else {
            (false, false)
        };
    let require_user_presence = true;
    let enterprise_attestation_possible = false;
    let extensions = None;
    let credential_parameters = request_value
        .clone()
        .get("pubKeyCredParams")
        .ok_or_else(|| {
            WebAuthnError::Internal(
                "Request JSON missing or invalid `pubKeyCredParams` key".to_string(),
            )
        })
        .and_then(|val| {
            serde_json::from_str::<Vec<PublicKeyCredentialParameters>>(&val.to_string()).map_err(
                |e| {
                    WebAuthnError::Internal(format!(
                        "Request JSON missing or invalid `pubKeyCredParams` key: {e}"
                    ))
                },
            )
        })?;
    let excluded_credentials = other_options.excluded_credentials.unwrap_or(Vec::new());

    make_credential(
        challenge,
        origin,
        !same_origin,
        rp,
        &user,
        require_resident_key,
        require_user_presence,
        require_user_verification,
        credential_parameters,
        excluded_credentials,
        enterprise_attestation_possible,
        extensions,
    )
    .map(|(response, cred_source)| (response, cred_source, user))
}

pub(crate) fn make_credential(
    challenge: String,
    origin: &str,
    cross_origin: bool,
    rp_entity: RelyingParty,
    user_entity: &User,
    require_resident_key: bool,
    require_user_presence: bool,
    require_user_verification: bool,
    cred_pub_key_algs: Vec<PublicKeyCredentialParameters>,
    exclude_credential_descriptor_list: Vec<CredentialDescriptor>,
    enterprise_attestation_possible: bool,
    extensions: Option<()>,
) -> Result<(CreatePublicKeyCredentialResponse, CredentialSource), WebAuthnError> {
    // Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.
    // TODO:
    let supported_algorithms: [CoseKeyType; 3] = [
        CoseKeyType::ES256_P256,
        CoseKeyType::EDDSA_ED25519,
        CoseKeyType::RS256,
    ];

    // When this operation is invoked, the authenticator MUST perform the following procedure:
    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    let cross_origin_str = if cross_origin { "true" } else { "false" };
    let client_data_json = format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}");
    let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
        .as_ref()
        .to_owned();
    if client_data_hash.len() != 32 {
        return Err(WebAuthnError::Unknown);
    }
    if rp_entity.id.is_empty() || rp_entity.name.is_empty() {
        return Err(WebAuthnError::Unknown);
    }
    if user_entity.id.is_empty() || user_entity.name.is_empty() {
        return Err(WebAuthnError::Unknown);
    }

    // Check if at least one of the specified combinations of PublicKeyCredentialType and cryptographic parameters in credTypesAndPubKeyAlgs is supported. If not, return an error code equivalent to "NotSupportedError" and terminate the operation.
    let cred_pub_key_parameters = match cred_pub_key_algs
        .iter()
        .filter(|p| p.cred_type == "public-key")
        .find(|p| {
            if let Ok(ref key_type) = (*p).try_into() {
                supported_algorithms.contains(key_type)
            } else {
                false
            }
        }) {
        Some(cred_pub_key_parameters) => cred_pub_key_parameters,
        None => return Err(WebAuthnError::NotSupported),
    };

    // For each descriptor of excludeCredentialDescriptorList:
    for cd in exclude_credential_descriptor_list.iter() {
        // If looking up descriptor.id in this authenticator returns non-null,
        // and the returned item's RP ID and type match rpEntity.id and
        // excludeCredentialDescriptorList.type respectively, then collect an
        // authorization gesture confirming user consent for creating a new
        // credential. The authorization gesture MUST include a test of user
        // presence.
        if let Some((found, rp)) = lookup_stored_credentials(&cd.id) {
            if rp.id == rp_entity.id && found.cred_type == cd.cred_type {
                let has_consent: bool = ask_disclosure_consent();
                // If the user confirms consent to create a new credential
                if has_consent {
                    // return an error code equivalent to "InvalidStateError" and terminate the operation.
                    return Err(WebAuthnError::InvalidState);
                }
                // does not consent to create a new credential
                else {
                    // return an error code equivalent to "NotAllowedError" and terminate the operation.
                    return Err(WebAuthnError::NotAllowed);
                }
                // Note: The purpose of this authorization gesture is not to proceed with creating a credential, but for privacy reasons to authorize disclosure of the fact that descriptor.id is bound to this authenticator. If the user consents, the client and Relying Party can detect this and guide the user to use a different authenticator. If the user does not consent, the authenticator does not reveal that descriptor.id is bound to it, and responds as if the user simply declined consent to create a credential.
            }
        }
    }

    // If requireResidentKey is true and the authenticator cannot store a client-side discoverable public key credential source, return an error code equivalent to "ConstraintError" and terminate the operation.
    if require_resident_key && !CAN_CREATE_DISCOVERABLE_CREDENTIAL {
        return Err(WebAuthnError::Constraint);
    }

    // If requireUserVerification is true and the authenticator cannot perform user verification, return an error code equivalent to "ConstraintError" and terminate the operation.
    if require_user_verification && !is_user_verification_available() {
        return Err(WebAuthnError::Constraint);
    }
    // Collect an authorization gesture confirming user consent for creating a
    // new credential. The prompt for the authorization gesture is shown by the
    // authenticator if it has its own output capability, or by the user agent
    // otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name,
    // userEntity.name and userEntity.displayName, if possible.
    // If requireUserVerification is true, the authorization gesture MUST include user verification.

    // If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
    if collect_authorization_gesture(require_user_verification, require_user_presence).is_err() {
        // If the user does not consent or if user verification fails, return an error code equivalent to "NotAllowedError" and terminate the operation.
        return Err(WebAuthnError::NotAllowed);
    }
    let mut flags = if require_user_verification {
        AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED
    } else {
        AuthenticatorDataFlags::USER_PRESENT
    };

    // Once the authorization gesture has been completed and user consent has been obtained, generate a new credential object:
    // Let (publicKey, privateKey) be a new pair of cryptographic keys using the combination of PublicKeyCredentialType and cryptographic parameters represented by the first item in credTypesAndPubKeyAlgs that is supported by this authenticator.
    let key_type = cred_pub_key_parameters
        .try_into()
        .map_err(|_| WebAuthnError::Unknown)?;
    let key_pair = create_key_pair(key_type)?;
    // Let userHandle be userEntity.id.
    let user_handle = URL_SAFE_NO_PAD
        .decode(user_entity.id.clone())
        .map_err(|_| WebAuthnError::Unknown)?;

    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
    // Let credentialId be a new credential id.
    // Note: We'll always create a discoverable credential, so generate a random credential ID.
    let credential_id: Vec<u8> = ring::rand::generate::<[u8; 16]>(&SystemRandom::new())
        .map_err(|_e| WebAuthnError::Unknown)?
        .expose()
        .into();

    // Let credentialSource be a new public key credential source with the fields:
    let credential_source = CredentialSource {
        // type
        // public-key.
        cred_type: PublicKeyCredentialType::PublicKey,
        // Set credentialSource.id to credentialId.
        id: credential_id.to_vec(),
        // privateKey
        // privateKey
        private_key: key_pair.clone(),
        key_parameters: cred_pub_key_parameters.clone(),
        // rpId
        // rpEntity.id
        rp_id: rp_entity.id,
        // userHandle
        // userHandle
        user_handle: Some(user_handle),
        // otherUI
        // Any other information the authenticator chooses to include.
        other_ui: None,
    };

    // If any error occurred while creating the new credential object, return an error code equivalent to "UnknownError" and terminate the operation.

    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    if let Some(extensions) = extensions {
        process_authenticator_extensions(extensions)
            .expect("Extension processing not yet supported");
    };

    // If the authenticator:

    let counter_type = WebAuthnDeviceCounterType::PerCredential;
    let signature_counter: u32 = match counter_type {
        // is a U2F device
        // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
        // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => todo!(), // authenticator.sign_count
        // supports a per credential signature counter

        // allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        WebAuthnDeviceCounterType::PerCredential => 0,
        // does not support a signature counter

        // let the signature counter value for the new credential be constant at zero.
        WebAuthnDeviceCounterType::Unsupported => 0,
    };

    // Let attestedCredentialData be the attested credential data byte array including the credentialId and publicKey.
    let aaguid = vec![0_u8; 16];
    let public_key = encode_pkcs8_key(key_type, &key_pair).map_err(|_| WebAuthnError::Unknown)?;
    let attested_credential_data =
        create_attested_credential_data(&credential_id, &public_key, &aaguid)?;

    flags = flags | AuthenticatorDataFlags::ATTESTED_CREDENTIALS;
    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data, including attestedCredentialData as the attestedCredentialData and processedExtensions, if any, as the extensions.
    let rp_id_hash = ring::digest::digest(&digest::SHA256, &credential_source.rp_id.as_bytes());
    let authenticator_data = create_authenticator_data(
        rp_id_hash.as_ref(),
        &flags,
        signature_counter,
        Some(&attested_credential_data),
        None,
    );

    // Create an attestation object for the new credential using the procedure specified in § 6.5.4 Generating an Attestation Object, using an authenticator-chosen attestation statement format, authenticatorData, and hash, as well as taking into account the value of enterpriseAttestationPossible. For more details on attestation, see § 6.5 Attestation.
    // TODO: attestation not supported for now
    let signature = sign_attestation(&authenticator_data, &client_data_hash, &key_pair, &key_type)?;
    let attestation_statment = AttestationStatement::Packed {
        algorithm: key_type.algorithm(),
        signature,
        certificates: vec![],
    };
    let attestation_object = webauthn::create_attestation_object(
        &authenticator_data,
        &attestation_statment,
        enterprise_attestation_possible,
    )?;

    // On successful completion of this operation, the authenticator returns the attestation object to the client.
    let response = CreatePublicKeyCredentialResponse::new(
        credential_id,
        attestation_object,
        authenticator_data,
        client_data_json,
        None,
        String::new(),
        String::from("platform"),
    );
    Ok((response, credential_source))
}

fn get_credential(
    rp_entity: RelyingParty,

    challenge: String,
    origin: &str,
    cross_origin: bool,
    top_origin: Option<String>,
    allow_credential_descriptor_list: Option<Vec<CredentialDescriptor>>,
    require_user_presence: bool,
    require_user_verification: bool,
    enterprise_attestation_possible: bool,
    attestation_formats: Vec<AttestationStatementFormat>,
    stored_credentials: HashMap<Vec<u8>, CredentialSource>,

    extensions: Option<()>,
) -> Result<GetPublicKeyCredentialResponse, WebAuthnError> {
    // Note: Before performing this operation, all other operations in progress in the authenticator session MUST be aborted by running the authenticatorCancel operation.

    // When this method is invoked, the authenticator MUST perform the following procedure:

    // Check if all the supplied parameters are syntactically well-formed and of the correct length. If not, return an error code equivalent to "UnknownError" and terminate the operation.
    let cross_origin_str = if cross_origin { "true" } else { "false" };
    let client_data_json = format!("{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross_origin_str}}}");
    let client_data_hash = digest::digest(&digest::SHA256, client_data_json.as_bytes())
        .as_ref()
        .to_owned();
    if client_data_hash.len() != 32 {
        return Err(WebAuthnError::Unknown);
    }

    // Let credentialOptions be a new empty set of public key credential sources.
    // If allowCredentialDescriptorList was supplied, then for each descriptor of allowCredentialDescriptorList:
    let credential_options: Vec<&CredentialSource> =
        if let Some(ref allowed_credentials) = allow_credential_descriptor_list {
            // Let credSource be the result of looking up descriptor.id in this authenticator.
            // If credSource is not null, append it to credentialOptions.
            allowed_credentials
                .iter()
                .filter_map(|cred| stored_credentials.get(&cred.id))
                // Remove any items from credentialOptions whose rpId is not equal to rpId.
                .filter(|cred_source| cred_source.rp_id == rp_entity.id)
                .collect()
        } else {
            // Otherwise (allowCredentialDescriptorList was not supplied), for each key → credSource of this authenticator’s credentials map, append credSource to credentialOptions.
            stored_credentials
                .values()
                // Remove any items from credentialOptions whose rpId is not equal to rpId.
                .filter(|cred_source| cred_source.rp_id == rp_entity.id)
                .collect()
        };

    // If credentialOptions is now empty, return an error code equivalent to "NotAllowedError" and terminate the operation.
    if credential_options.is_empty() {
        return Err(WebAuthnError::NotAllowed);
    }
    // Prompt the user to select a public key credential source selectedCredential from credentialOptions. Collect an authorization gesture confirming user consent for using selectedCredential. The prompt for the authorization gesture may be shown by the authenticator if it has its own output capability, or by the user agent otherwise.
    // TODO, already done? Move up to D-Bus call
    // If requireUserVerification is true, the authorization gesture MUST include user verification.
    // If requireUserPresence is true, the authorization gesture MUST include a test of user presence.
    // If the user does not consent, return an error code equivalent to "NotAllowedError" and terminate the operation.
    if collect_authorization_gesture(require_user_presence, require_user_verification).is_err() {
        return Err(WebAuthnError::NotAllowed);
    }
    let flags = if require_user_verification {
        AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED
    } else {
        AuthenticatorDataFlags::USER_VERIFIED
    };

    // TODO: pass selected_credential to this method
    let selected_credential = credential_options[0];
    // Let processedExtensions be the result of authenticator extension processing for each supported extension identifier → authenticator extension input in extensions.
    if let Some(extensions) = extensions {
        // TODO: support extensions
        process_authenticator_extensions(extensions)
            .expect("Processing extensions not supported yet.");
    }

    // Increment the credential associated signature counter or the global signature counter value, depending on which approach is implemented by the authenticator, by some positive value. If the authenticator does not implement a signature counter, let the signature counter value remain constant at zero.
    let signature_counter = 0;
    /*  TODO
    let counter_type = WebAuthnDeviceCounterType::PerCredential;
    let signature_counter: u32 = match counter_type {
        // is a U2F device
        // let the signature counter value for the new credential be zero. (U2F devices may support signature counters but do not return a counter when making a credential. See [FIDO-U2F-Message-Formats].)
        WebAuthnDeviceCounterType::U2F => 0,
        // supports a global signature counter
        // Use the global signature counter's actual value when generating authenticator data.
        WebAuthnDeviceCounterType::Global => todo!(), // authenticator.sign_count
        // supports a per credential signature counter

        // allocate the counter, associate it with the new credential, and initialize the counter value as zero.
        WebAuthnDeviceCounterType::PerCredential => cred_source.,
        // does not support a signature counter

        // let the signature counter value for the new credential be constant at zero.
        WebAuthnDeviceCounterType::Unsupported => 0,
    };
    */

    // If attestationFormats:
    // is not empty
    //     let attestationFormat be the first supported attestation statement format from attestationFormats, taking into account enterpriseAttestationPossible. If none are supported, fallthrough to:
    // is empty
    //     let attestationFormat be the attestation statement format most preferred by this authenticator. If it does not support attestation during assertion then let this be none.
    let supported_formats = [AttestationStatementFormat::Packed];
    let preferred_format = AttestationStatementFormat::None;
    let attestation_format = attestation_formats
        .iter()
        .find(|f| supported_formats.contains(f))
        .unwrap_or(&preferred_format);

    let key_type = (&selected_credential.key_parameters)
        .try_into()
        .map_err(|_| WebAuthnError::Unknown)?;
    let public_key = encode_pkcs8_key(key_type, &selected_credential.private_key)
        .map_err(|_| WebAuthnError::Unknown)?;

    // TODO: Assign AAGUID?
    let aaguid = vec![0_u8; 16];
    let attested_credential_data = if *attestation_format != AttestationStatementFormat::None {
        create_attested_credential_data(&selected_credential.id, &public_key, &aaguid).ok()
    } else {
        None
    };
    // Let authenticatorData be the byte array specified in § 6.1 Authenticator Data including processedExtensions, if any, as the extensions and excluding attestedCredentialData. This authenticatorData MUST include attested credential data if, and only if, attestationFormat is not none.
    let rp_id_hash = digest::digest(&digest::SHA256, selected_credential.rp_id.as_bytes());
    let authenticator_data = create_authenticator_data(
        rp_id_hash.as_ref(),
        &flags,
        signature_counter,
        attested_credential_data.as_deref(),
        None,
    );
    // Let signature be the assertion signature of the concatenation authenticatorData || hash using the privateKey of selectedCredential as shown in Figure , below. A simple, undelimited concatenation is safe to use here because the authenticator data describes its own length. The hash of the serialized client data (which potentially has a variable length) is always the last element.
    let signature = sign_attestation(
        &authenticator_data,
        &client_data_hash,
        &selected_credential.private_key,
        &key_type,
    )?;

    // If any error occurred then return an error code equivalent to "UnknownError" and terminate the operation.
    // Return to the user agent:
    let response = GetPublicKeyCredentialResponse {
        cred_type: "public-key".to_string(),
        client_data_json,

        // selectedCredential.id, if either a list of credentials (i.e., allowCredentialDescriptorList) of length 2 or greater was supplied by the client, or no such list was supplied.
        // Note: If, within allowCredentialDescriptorList, the client supplied exactly one credential and it was successfully employed, then its credential ID is not returned since the client already knows it. This saves transmitting these bytes over what may be a constrained connection in what is likely a common case.
        raw_id: if allow_credential_descriptor_list.map_or(true, |l| l.len() > 1) {
            Some(selected_credential.id.clone())
        } else {
            None
        },

        // authenticatorData
        authenticator_data,

        // signature
        signature,

        // selectedCredential.userHandle
        // Note: In cases where allowCredentialDescriptorList was supplied the returned userHandle value may be null, see: userHandleResult.
        user_handle: selected_credential.user_handle.clone(),
        attachment_modality: String::from("platform"),
        extensions: None,
    };
    Ok(response)
    // If the authenticator cannot find any credential corresponding to the specified Relying Party that matches the specified criteria, it terminates the operation and returns an error.
}

fn create_key_pair(parameters: CoseKeyType) -> Result<Vec<u8>, WebAuthnError> {
    let rng = &SystemRandom::new();
    let key_pair = match parameters {
        CoseKeyType::ES256_P256 => {
            EcdsaKeyPair::generate_pkcs8(P256, rng).map(|d| d.as_ref().to_vec())
        }
        CoseKeyType::EDDSA_ED25519 => {
            Ed25519KeyPair::generate_pkcs8(rng).map(|d| d.as_ref().to_vec())
        }
        CoseKeyType::RS256 => {
            let rsa_key = Rsa::generate(2048).unwrap();
            let private_key = PKey::from_rsa(rsa_key).unwrap();
            let pkcs8 = private_key.private_key_to_pkcs8().unwrap();
            Ok(pkcs8.to_vec())
        }
        _ => todo!("Unknown signature algorithm given pair generated"),
    };
    key_pair.map_err(|_e| WebAuthnError::Unknown)
}

fn lookup_stored_credentials(id: &[u8]) -> Option<(CredentialDescriptor, RelyingParty)> {
    todo!()
}

fn ask_disclosure_consent() -> bool {
    todo!();
}

fn is_user_verification_available() -> bool {
    todo!();
}

fn collect_authorization_gesture(
    _require_user_presence: bool,
    _require_user_verification: bool,
) -> Result<(), WebAuthnError> {
    // todo!();
    Ok(())
}

fn process_authenticator_extensions(_extensions: ()) -> Result<(), WebAuthnError> {
    todo!();
}

fn sign_attestation(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    key_pair: &[u8],
    key_type: &CoseKeyType,
) -> Result<Vec<u8>, WebAuthnError> {
    let signed_data: Vec<u8> = [authenticator_data, client_data_hash].concat();
    let rng = &SystemRandom::new();
    match key_type {
        CoseKeyType::ES256_P256 => {
            let ecdsa = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                key_pair,
                &SystemRandom::new(),
            )
            .unwrap();
            Ok(ecdsa.sign(rng, &signed_data).unwrap().as_ref().to_vec())
        }
        CoseKeyType::EDDSA_ED25519 => {
            let eddsa = Ed25519KeyPair::from_pkcs8(key_pair).unwrap();
            Ok(eddsa.sign(&signed_data).as_ref().to_vec())
        }
        CoseKeyType::RS256 => {
            let rsa = RsaKeyPair::from_pkcs8(key_pair).unwrap();
            let mut signature = vec![0; rsa.public().modulus_len()];
            let _ = rsa.sign(&RSA_PKCS1_SHA256, rng, &signed_data, &mut signature);
            Ok(signature)
        }
        _ => Err(WebAuthnError::NotSupported),
    }
}

enum WebAuthnDeviceCounterType {
    /// Authenticator is a U2F device (and therefore does not support a counter
    /// on registration and may or may not support a counter on assertion).
    U2F,
    /// Authenticator supports a global signature counter.
    Global,
    /// Authenticator supports a per credential signature counter.
    PerCredential,
    /// Authenticator does not support a signature counter.
    Unsupported,
}

#[cfg(test)]
mod test {
    use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use libwebauthn::fido::AuthenticatorDataFlags;
    use ring::digest::{digest, SHA256};

    use crate::cose::encode_pkcs8_key;

    use crate::webauthn::{
        create_attestation_object, AttestationStatement, CredentialSource,
        PublicKeyCredentialParameters, PublicKeyCredentialType,
    };

    use super::{create_attested_credential_data, create_authenticator_data, sign_attestation};

    #[test]
    fn test_attestation() {
        let key_file = std::fs::read("private-key1.pk8").unwrap();
        // let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_file, &SystemRandom::new()).unwrap();
        let key_parameters = PublicKeyCredentialParameters {
            alg: -7,
            cred_type: "public-key".to_string(),
        };
        let key_type = (&key_parameters).try_into().unwrap();
        let public_key = encode_pkcs8_key(key_type, &key_file).unwrap();
        let signature_counter = 1u32;
        let credential_id = [
            0x92, 0x11, 0xb7, 0x6d, 0x8b, 0x19, 0xf9, 0x50, 0x6c, 0x2d, 0x75, 0x2f, 0x09, 0xc4,
            0x3c, 0x5a, 0xeb, 0xf3, 0x36, 0xf6, 0xba, 0x89, 0x66, 0xdc, 0x6e, 0x71, 0x93, 0x52,
            0x08, 0x72, 0x1d, 0x16,
        ]
        .to_vec();
        let aaguid = [
            01, 02, 03, 04, 05, 06, 07, 08, 01, 02, 03, 04, 05, 06, 07, 08,
        ];
        let attested_credential_data =
            create_attested_credential_data(&credential_id, &public_key, &aaguid).unwrap();
        let user_handle = [
            0x64, 0x47, 0x56, 0x7a, 0x64, 0x47, 0x46, 0x69, 0x65, 0x6e, 0x6f,
        ]
        .to_vec();
        let credential_source = CredentialSource {
            cred_type: PublicKeyCredentialType::PublicKey,
            id: credential_id,
            private_key: key_file.clone(),
            key_parameters: PublicKeyCredentialParameters::new(key_type.algorithm().into()),
            rp_id: "webauthn.io".to_string(),
            user_handle: Some(user_handle),
            other_ui: None,
        };

        let flags = AuthenticatorDataFlags::USER_PRESENT
            | AuthenticatorDataFlags::USER_VERIFIED
            | AuthenticatorDataFlags::ATTESTED_CREDENTIALS;
        let authenticator_data = create_authenticator_data(
            &credential_source.rp_id_hash(),
            &flags,
            signature_counter,
            Some(&attested_credential_data),
            None,
        );
        let client_data_encoded = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWWlReFY0VWhjZk9pUmZBdkF4bWpEakdhaUVXbkYtZ0ZFcWxndmdEaWsyakZiSGhoaVlxUGJqc0F5Q0FrbDlMUGQwRGRQaHNNb2luY0cxckV5cFlXUVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ";
        let client_data = URL_SAFE_NO_PAD.decode(client_data_encoded).unwrap();
        let client_data_hash = digest(&SHA256, &client_data).as_ref().to_vec();
        let signature =
            sign_attestation(&authenticator_data, &client_data_hash, &key_file, &key_type).unwrap();
        let att_stmt = AttestationStatement::Packed {
            algorithm: key_type.algorithm(),
            signature,
            certificates: vec![],
        };
        let attestation_object =
            create_attestation_object(&authenticator_data, &att_stmt, false).unwrap();
        let expected = std::fs::read("output.bin").unwrap();
        assert_eq!(expected, attestation_object);
    }
}
