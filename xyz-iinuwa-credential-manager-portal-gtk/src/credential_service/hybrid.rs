use std::fmt::Debug;

use async_stream::stream;
use futures_lite::Stream;
use libwebauthn::transport::cable::qr_code_device::{CableQrCodeDevice, QrCodeOperationHint};
use libwebauthn::transport::Device;
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

use crate::dbus::CredentialRequest;

use super::AuthenticatorResponse;

pub(crate) trait HybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static;
}

#[derive(Debug)]
pub struct InternalHybridHandler {}
impl InternalHybridHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl HybridHandler for InternalHybridHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = HybridEvent> + Unpin + Send + Sized + 'static {
        let request = request.clone();
        let (tx, rx) = async_std::channel::unbounded();
        tokio::spawn(async move {
            let hint = match request {
                CredentialRequest::CreatePublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::MakeCredential
                }
                CredentialRequest::GetPublicKeyCredentialRequest(_) => {
                    QrCodeOperationHint::GetAssertionRequest
                }
            };
            let mut device = CableQrCodeDevice::new_transient(hint);
            let qr_code = device.qr_code.to_string();
            if let Err(err) = tx.send(HybridStateInternal::Init(qr_code)).await {
                tracing::error!("Failed to send caBLE update: {:?}", err);
                return;
            };
            tokio::spawn(async move {
                let mut channel = match device.channel().await {
                    Ok((channel, _)) => channel,
                    Err(e) => {
                        tracing::error!("Failed to open hybrid channel: {:?}", e);
                        panic!();
                    }
                };
                if let Err(err) = tx.send(HybridStateInternal::Connected).await {
                    tracing::error!("Failed to send caBLE update: {:?}", err)
                }
                let response: AuthenticatorResponse = loop {
                    match &request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_request) => {
                            match channel.webauthn_make_credential(make_request).await {
                                Ok(response) => break Ok(response.into()),
                                Err(WebAuthnError::Ctap(ctap_error)) => {
                                    if ctap_error.is_retryable_user_error() {
                                        tracing::debug!("Oops, try again! Error: {}", ctap_error);
                                        continue;
                                    }
                                    break Err(WebAuthnError::Ctap(ctap_error));
                                }
                                Err(err) => break Err(err),
                            };
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_request) => {
                            match channel.webauthn_get_assertion(get_request).await {
                                Ok(response) => break Ok(response.into()),
                                Err(WebAuthnError::Ctap(ctap_error)) => {
                                    if ctap_error.is_retryable_user_error() {
                                        println!("Oops, try again! Error: {}", ctap_error);
                                        continue;
                                    }
                                    break Err(WebAuthnError::Ctap(ctap_error));
                                }
                                Err(err) => break Err(err),
                            };
                        }
                    }
                }
                .unwrap();
                if let Err(err) = tx.send(HybridStateInternal::Completed(response)).await {
                    tracing::error!("Failed to send caBLE update: {:?}", err)
                }
            });
        });
        Box::pin(stream! {
            while let Ok(state) = rx.recv().await {
                yield HybridEvent { state }
            }
        })
    }
}

#[derive(Clone, Debug)]
pub(super) enum HybridStateInternal {
    /// Awaiting BLE advert from phone. Content is the FIDO string to be
    /// displayed to the user, which contains QR secret and public key.
    Init(String),

    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Hybrid tunnel has been established
    Connected,

    /// Authenticator data
    Completed(AuthenticatorResponse),

    // TODO(cancellation)
    // This isn't actually sent from the server.
    #[allow(dead_code)]
    UserCancelled,
}

pub struct HybridEvent {
    pub(super) state: HybridStateInternal,
}

#[derive(Clone, Debug)]
pub enum HybridState {
    /// Awaiting BLE advert from phone. Content is the FIDO string to be displayed to the user, which contains QR secret
    /// and public key.
    Init(String),

    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Tunnel is established, waiting for user to release credential on their device.
    Connected,

    /// Authenticator data
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

impl From<HybridStateInternal> for HybridState {
    fn from(value: HybridStateInternal) -> Self {
        match value {
            HybridStateInternal::Init(qr_code) => HybridState::Init(qr_code),
            HybridStateInternal::Connecting => HybridState::Connecting,
            HybridStateInternal::Connected => HybridState::Connected,
            HybridStateInternal::Completed(_) => HybridState::Completed,
            HybridStateInternal::UserCancelled => HybridState::UserCancelled,
        }
    }
}

#[cfg(test)]
pub(super) mod test {
    use std::task::Poll;

    use futures_lite::Stream;
    use libwebauthn::{
        fido::{AuthenticatorData, AuthenticatorDataFlags},
        ops::webauthn::{Assertion, GetAssertionResponse},
        proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport},
    };

    use crate::dbus::CredentialRequest;

    use super::{HybridEvent, HybridHandler, HybridStateInternal};
    #[derive(Debug)]
    pub struct DummyHybridHandler {
        stream: DummyHybridStateStream,
    }

    impl DummyHybridHandler {
        #[cfg(test)]
        pub fn new(states: Vec<HybridStateInternal>) -> Self {
            Self {
                stream: DummyHybridStateStream { states },
            }
        }
    }

    impl Default for DummyHybridHandler {
        fn default() -> Self {
            Self {
                stream: DummyHybridStateStream::default(),
            }
        }
    }
    impl HybridHandler for DummyHybridHandler {
        fn start(
            &self,
            _request: &CredentialRequest,
        ) -> impl Stream<Item = HybridEvent> + Send + Sized + Unpin + 'static {
            self.stream.clone()
        }
    }

    #[derive(Clone, Debug)]
    pub struct DummyHybridStateStream {
        states: Vec<HybridStateInternal>,
    }

    impl Default for DummyHybridStateStream {
        fn default() -> Self {
            let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
            // SHA256("webauthn.io")
            let rp_id_hash = [
                0x74, 0xa6, 0xea, 0x92, 0x13, 0xc9, 0x9c, 0x2f, 0x74, 0xb2, 0x24, 0x92, 0xb3, 0x20,
                0xcf, 0x40, 0x26, 0x2a, 0x94, 0xc1, 0xa9, 0x50, 0xa0, 0x39, 0x7f, 0x29, 0x25, 0xb,
                0x60, 0x84, 0x1e, 0xf0,
            ];

            let auth_data = AuthenticatorData {
                rp_id_hash,
                flags: AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::USER_VERIFIED,
                signature_count: 1,
                attested_credential: None,
                extensions: None,
            };

            let assertion = Assertion {
                credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                    id: vec![0xca, 0xb1, 0xe].into(),
                    r#type: libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialType::PublicKey,
                    transports: Some(vec![Ctap2Transport::Hybrid]),
                }),
                authenticator_data: auth_data,
                signature: Vec::new(),
                user: None,
                credentials_count: Some(1),
                user_selected: None,
                large_blob_key: None,
                unsigned_extensions_output: None,
                enterprise_attestation: None,
                attestation_statement: None,
            };
            let response = GetAssertionResponse {
                assertions: vec![assertion],
            };
            DummyHybridStateStream {
                states: vec![
                    HybridStateInternal::Init(qr_code),
                    HybridStateInternal::Connecting,
                    HybridStateInternal::Completed(response.into()),
                ],
            }
        }
    }

    impl Stream for DummyHybridStateStream {
        type Item = HybridEvent;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            if self.states.len() == 0 {
                Poll::Ready(None)
            } else {
                let state = (self.get_mut()).states.remove(0);
                Poll::Ready(Some(HybridEvent { state }))
            }
        }
    }
}
