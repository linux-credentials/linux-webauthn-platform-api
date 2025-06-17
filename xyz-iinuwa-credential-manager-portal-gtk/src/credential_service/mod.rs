pub mod hybrid;
mod server;
pub mod usb;

use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use futures_lite::{FutureExt, Stream, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
};

use crate::{
    credential_service::{hybrid::HybridEvent, usb::UsbEvent},
    dbus::{CredentialRequest, CredentialResponse},
    view_model::{Device, Transport},
};

use hybrid::{HybridHandler, HybridState, HybridStateInternal};
use usb::{UsbHandler, UsbStateInternal};
pub use {
    server::{CredentialManagementClient, CredentialServiceClient, InProcessServer},
    usb::UsbState,
};

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler, U: UsbHandler> {
    devices: Vec<Device>,

    cred_request: Mutex<Option<CredentialRequest>>,
    // Place to store data to be returned to the caller
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,

    hybrid_handler: H,
    usb_handler: U,
}

impl<H: HybridHandler + Debug, U: UsbHandler + Debug> CredentialService<H, U>
where
// <H as HybridHandler>::Stream: Unpin + Send + Sized + 'static,
// <U as UsbHandler>::Stream: Unpin + Send + Sized + 'static,
{
    pub fn new(hybrid_handler: H, usb_handler: U) -> Self {
        let devices = vec![
            Device {
                id: String::from("0"),
                transport: Transport::Usb,
            },
            Device {
                id: String::from("1"),
                transport: Transport::HybridQr,
            },
        ];
        Self {
            devices,

            cred_request: Mutex::new(None),
            cred_response: Arc::new(Mutex::new(None)),

            hybrid_handler,
            usb_handler,
        }
    }

    pub fn init_request(&self, request: &CredentialRequest) -> Result<(), String> {
        let mut cred_request = self.cred_request.lock().unwrap();
        if cred_request.is_some() {
            Err("Already a request in progress.".to_string())
        } else {
            _ = cred_request.insert(request.clone());
            Ok(())
        }
    }

    async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    fn get_hybrid_credential(&self) -> Pin<Box<dyn Stream<Item = HybridState> + Send + 'static>> {
        let guard = self.cred_request.lock().unwrap();
        let cred_request = guard.clone().unwrap();
        let stream = self.hybrid_handler.start(&cred_request);
        let cred_response = self.cred_response.clone();
        Box::pin(HybridStateStream {
            inner: stream,
            cred_response,
        })
    }

    fn get_usb_credential(&self) -> Pin<Box<dyn Stream<Item = UsbState> + Send + 'static>> {
        let guard = self.cred_request.lock().unwrap();
        let cred_request = guard.clone().unwrap();
        let stream = self.usb_handler.start(&cred_request);
        Box::pin(UsbStateStream {
            inner: stream,
            cred_response: self.cred_response.clone(),
        })
    }

    pub fn complete_auth(&self) -> Option<CredentialResponse> {
        self.cred_request.lock().unwrap().take();
        let mut cred_response = self.cred_response.lock().unwrap();
        cred_response.take()
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl<H> Stream for HybridStateStream<H>
where
    H: Stream<Item = HybridEvent> + Unpin + Sized,
{
    type Item = HybridState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let cred_response = &self.cred_response.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(HybridEvent { state })) => {
                if let HybridStateInternal::Completed(hybrid_response) = &state {
                    let response = match hybrid_response {
                        AuthenticatorResponse::CredentialCreated(make_credential_response) => {
                            CredentialResponse::from_make_credential(
                                make_credential_response,
                                &["hybrid"],
                                "cross-platform",
                            )
                        }
                        AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                            CredentialResponse::from_get_assertion(
                                // When doing hybrid, the authenticator is capable of displaying it's own UI.
                                // So we assume here, it only ever returns one assertion.
                                // In case this doesn't hold true, we have to implement credential selection here,
                                // as is done for USB.
                                &get_assertion_response.assertions[0],
                                "cross-platform",
                            )
                        }
                    };
                    let mut cred_response = cred_response.lock().unwrap();
                    cred_response.replace(response);
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

struct UsbStateStream<H> {
    inner: H,
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl<H> Stream for UsbStateStream<H>
where
    H: Stream<Item = UsbEvent> + Unpin + Sized,
{
    type Item = UsbState;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let cred_response = &self.cred_response.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(UsbEvent { state })) => {
                if let UsbStateInternal::Completed(response) = &state {
                    let mut cred_response = cred_response.lock().unwrap();
                    cred_response.replace(response.clone());
                }
                Poll::Ready(Some(state.into()))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

#[derive(Debug, Clone)]
enum AuthenticatorResponse {
    CredentialCreated(MakeCredentialResponse),
    CredentialsAsserted(GetAssertionResponse),
}

#[derive(Debug, Clone)]
pub enum Error {
    AuthenticatorError,
}

impl From<MakeCredentialResponse> for AuthenticatorResponse {
    fn from(value: MakeCredentialResponse) -> Self {
        Self::CredentialCreated(value)
    }
}

impl From<GetAssertionResponse> for AuthenticatorResponse {
    fn from(value: GetAssertionResponse) -> Self {
        Self::CredentialsAsserted(value)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use async_std::stream::StreamExt;

    use crate::{
        credential_service::usb::InProcessUsbHandler,
        dbus::{CreateCredentialRequest, CreatePublicKeyCredentialRequest, CredentialRequest},
    };

    use super::{
        hybrid::{test::DummyHybridHandler, HybridStateInternal},
        AuthenticatorResponse, CredentialService,
    };

    #[test]
    fn test_hybrid_sets_credential() {
        let request = create_credential_request();
        let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        let authenticator_response = create_authenticator_response();

        let hybrid_handler = DummyHybridHandler::new(vec![
            HybridStateInternal::Init(qr_code),
            HybridStateInternal::Connecting,
            HybridStateInternal::Completed(authenticator_response),
        ]);
        let usb_handler = InProcessUsbHandler {};
        let cred_service = Arc::new(CredentialService::new(hybrid_handler, usb_handler));
        cred_service.init_request(&request).unwrap();
        let mut stream = cred_service.get_hybrid_credential();
        async_std::task::block_on(async move { while let Some(_) = stream.next().await {} });
        let cred_service = Arc::try_unwrap(cred_service).unwrap();
        assert!(cred_service.complete_auth().is_some());
    }

    fn create_credential_request() -> CredentialRequest {
        let request_json = r#"
        {
            "rp": {
                "name": "webauthn.io",
                "id": "webauthn.io"
            },
            "user": {
                "id": "d2ViYXV0aG5pby0xMjM4OTF5",
                "name": "123891y",
                "displayName": "123891y"
            },
            "challenge": "Ox0AXQz7WUER7BGQFzvVrQbReTkS3sepVGj26qfUhhrWSarkDbGF4T4NuCY1aAwHYzOzKMJJ2YRSatetl0D9bQ",
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -8
                },
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "timeout": 60000,
            "excludeCredentials": [],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "requireResidentKey": false,
                "userVerification": "preferred"
            },
            "attestation": "none",
            "hints": [],
            "extensions": {
                "credProps": true
            }
        }"#.to_string();
        let (req, _) = CreateCredentialRequest {
            origin: Some("webauthn.io".to_string()),
            is_same_origin: Some(true),
            r#type: "public-key".to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest { request_json }),
        }
        .try_into_ctap2_request()
        .unwrap();
        CredentialRequest::CreatePublicKeyCredentialRequest(req)
    }

    fn create_authenticator_response() -> AuthenticatorResponse {
        use libwebauthn::{
            fido::{AuthenticatorData, AuthenticatorDataFlags},
            ops::webauthn::{Assertion, GetAssertionResponse},
            proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2Transport},
        };
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
        GetAssertionResponse {
            assertions: vec![assertion],
        }
        .into()
    }
}
