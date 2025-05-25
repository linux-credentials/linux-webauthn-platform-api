use std::fmt::Debug;
use std::task::Poll;

use async_std::stream::Stream;
use libwebauthn::fido::{AuthenticatorData, AuthenticatorDataFlags};
use libwebauthn::ops::webauthn::Assertion;
use libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;

pub(super) trait HybridHandler: HybridHandlerInternal + Debug + 'static {}

pub(crate) trait HybridHandlerInternal {
    type Stream: Stream<Item = HybridState>;
    fn start(&self) -> Self::Stream;
}

struct HybridStateStream {}
impl Stream for HybridStateStream {
    type Item = HybridState;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

#[derive(Debug)]
pub struct DummyHybridHandler {}
impl HybridHandler for DummyHybridHandler {}
impl HybridHandlerInternal for DummyHybridHandler {
    type Stream = DummyHybridStateStream;

    fn start(&self) -> Self::Stream {
        DummyHybridStateStream::default()
    }
}

#[derive(Clone)]
pub struct DummyHybridStateStream {
    states: Vec<HybridState>,
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
            // TODO: Do we need to add "hybrid" to Ctap2Transport?
            credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                id: vec![0xca, 0xb1, 0xe].into(),
                r#type: libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialType::PublicKey,
                transports: None,
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
        DummyHybridStateStream {
            states: vec![
                HybridState::Init(qr_code),
                HybridState::Waiting,
                HybridState::Connecting,
                HybridState::Completed(assertion),
            ],
        }
    }
}

impl Stream for DummyHybridStateStream {
    type Item = HybridState;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.states.len() == 0 {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some((self.get_mut()).states.remove(0)))
        }
    }
}

#[derive(Clone, Debug)]
pub enum HybridState {
    /// The FIDO string to be displayed to the user, which contains QR secret
    /// and public key.
    Init(String),

    /// Awaiting BLE advert from phone.
    Waiting,
    /// BLE advertisement has been received from phone, tunnel is being established
    Connecting,

    /// Authenticator data
    Completed(libwebauthn::ops::webauthn::Assertion),

    // This isn't actually sent from the server.
    UserCancelled,
}
