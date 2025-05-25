pub mod hybrid;

use std::{
    fmt::Debug,
    sync::{Arc, Mutex, OnceLock},
    task::Poll,
    time::Duration,
};

use async_std::stream::Stream;
use futures_lite::{FutureExt, StreamExt};
use libwebauthn::{
    self,
    ops::webauthn::{GetAssertionResponse, MakeCredentialResponse},
    transport::{hid::HidDevice, Device as _},
    webauthn::{Error as WebAuthnError, WebAuthn},
    UxUpdate,
};

use async_std::{
    channel::TryRecvError,
    sync::{Arc as AsyncArc, Mutex as AsyncMutex},
};
use tokio::runtime::Runtime;
use tracing::{debug, warn};

use crate::{
    dbus::{
        CredentialRequest, CredentialResponse, GetAssertionResponseInternal,
        MakeCredentialResponseInternal,
    },
    view_model::{Device, Transport},
};

use hybrid::{HybridHandler, HybridState};

#[derive(Debug)]
pub struct CredentialService<H: HybridHandler> {
    devices: Vec<Device>,

    usb_state: AsyncArc<AsyncMutex<UsbState>>,
    usb_uv_handler: UsbUvHandler,

    cred_request: CredentialRequest,
    // Place to store data to be returned to the caller
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,

    hybrid_handler: H,
}

impl<H: HybridHandler> CredentialService<H> {
    pub fn new(
        cred_request: CredentialRequest,
        cred_response: Arc<Mutex<Option<CredentialResponse>>>,
        hybrid_handler: H,
    ) -> Self {
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
        let usb_state = AsyncArc::new(AsyncMutex::new(UsbState::Idle));
        Self {
            devices,

            usb_state: usb_state.clone(),
            usb_uv_handler: UsbUvHandler::new(),

            cred_request,
            cred_response,

            hybrid_handler,
        }
    }

    pub async fn get_available_public_key_devices(&self) -> Result<Vec<Device>, ()> {
        Ok(self.devices.to_owned())
    }

    pub(crate) async fn poll_device_discovery_usb(&mut self) -> Result<UsbState, String> {
        debug!("polling for USB status");
        let prev_usb_state = self.usb_state.lock().await.clone();
        let next_usb_state = match prev_usb_state {
            UsbState::Idle | UsbState::Waiting => {
                let mut hid_devices = libwebauthn::transport::hid::list_devices().await.unwrap();
                if hid_devices.is_empty() {
                    let state = UsbState::Waiting;
                    *self.usb_state.lock().await = state.clone();
                    return Ok(state);
                } else if hid_devices.len() == 1 {
                    Ok(UsbState::Connected(hid_devices.swap_remove(0)))
                } else {
                    Ok(UsbState::SelectingDevice(hid_devices))
                }
            }
            UsbState::SelectingDevice(hid_devices) => {
                let (blinking_tx, mut blinking_rx) =
                    tokio::sync::mpsc::channel::<Option<HidDevice>>(hid_devices.len());
                let mut expected_answers = hid_devices.len();
                for mut device in hid_devices {
                    let tx = blinking_tx.clone();
                    tokio().spawn(async move {
                        let (mut channel, _state_rx) = device.channel().await.unwrap();
                        let res = channel
                            .blink_and_wait_for_user_presence(Duration::from_secs(300))
                            .await;
                        drop(channel);
                        match res {
                            Ok(true) => {
                                let _ = tx.send(Some(device)).await;
                            }
                            Ok(false) | Err(_) => {
                                let _ = tx.send(None).await;
                            }
                        }
                    });
                }
                let mut state = UsbState::Idle;
                while let Some(msg) = blinking_rx.recv().await {
                    expected_answers -= 1;
                    match msg {
                        Some(device) => {
                            state = UsbState::Connected(device);
                            break;
                        }
                        None => {
                            if expected_answers == 0 {
                                break;
                            } else {
                                continue;
                            }
                        }
                    }
                }
                Ok(state)
            }
            UsbState::Connected(mut device) => {
                let handler = self.usb_uv_handler.clone();
                let cred_request = self.cred_request.clone();
                let signal_tx = self.usb_uv_handler.signal_tx.clone();
                let pin_rx = self.usb_uv_handler.pin_rx.clone();
                tokio().spawn(async move {
                    let (mut channel, state_rx) = device.channel().await.unwrap();
                    tokio().spawn(async move {
                        handle_usb_updates(signal_tx, pin_rx, state_rx).await;
                        debug!("Reached end of USB update task");
                    });
                    match cred_request {
                        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                            loop {
                                match channel.webauthn_make_credential(&make_cred_request).await {
                                    Ok(response) => {
                                        handler
                                            .notify_ceremony_completed(
                                                AuthenticatorResponse::CredentialCreated(response),
                                            )
                                            .await;
                                        break;
                                    }
                                    Err(WebAuthnError::Ctap(ctap_error))
                                        if ctap_error.is_retryable_user_error() =>
                                    {
                                        warn!("Retrying WebAuthn make credential operation");
                                        continue;
                                    }
                                    Err(err) => {
                                        handler.notify_ceremony_failed(err.to_string()).await;
                                        break;
                                    }
                                };
                            }
                        }
                        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => {
                            loop {
                                match channel.webauthn_get_assertion(&get_cred_request).await {
                                    Ok(response) => {
                                        handler
                                            .notify_ceremony_completed(
                                                AuthenticatorResponse::CredentialsAsserted(
                                                    response,
                                                ),
                                            )
                                            .await;
                                        break;
                                    }
                                    Err(WebAuthnError::Ctap(ctap_error))
                                        if ctap_error.is_retryable_user_error() =>
                                    {
                                        warn!("Retrying WebAuthn get credential operation");
                                        continue;
                                    }
                                    Err(err) => {
                                        handler.notify_ceremony_failed(err.to_string()).await;
                                        break;
                                    }
                                };
                            }
                        }
                    };
                });
                match self.usb_uv_handler.wait_for_notification().await {
                    Ok(UsbUvMessage::NeedsPin { attempts_left }) => {
                        Ok(UsbState::NeedsPin { attempts_left })
                    }
                    Ok(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                        Ok(UsbState::NeedsUserVerification { attempts_left })
                    }
                    Ok(UsbUvMessage::NeedsUserPresence) => Ok(UsbState::NeedsUserPresence),
                    Ok(UsbUvMessage::ReceivedCredential(response)) => {
                        match response {
                            AuthenticatorResponse::CredentialCreated(r) => {
                                let mut cred_response = self.cred_response.lock().unwrap();
                                cred_response.replace(
                                    CredentialResponse::CreatePublicKeyCredentialResponse(
                                        MakeCredentialResponseInternal::new(
                                            r,
                                            vec![String::from("usb")],
                                            String::from("cross-platform"),
                                        ),
                                    ),
                                );
                                Ok(UsbState::Completed)
                            }
                            AuthenticatorResponse::CredentialsAsserted(r) => {
                                // at least one credential is returned from the authenticator
                                assert!(!r.assertions.is_empty());
                                if r.assertions.len() == 1 {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(
                                        CredentialResponse::GetPublicKeyCredentialResponse(
                                            GetAssertionResponseInternal::new(
                                                r.assertions[0].clone(),
                                                String::from("cross-platform"),
                                            ),
                                        ),
                                    );
                                    Ok(UsbState::Completed)
                                } else {
                                    todo!("need to support selection from multiple credentials");
                                }
                            }
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            UsbState::NeedsPin {
                attempts_left: Some(attempts_left),
            } if attempts_left <= 1 => Err("No more USB attempts left".to_string()),
            UsbState::NeedsUserVerification {
                attempts_left: Some(attempts_left),
            } if attempts_left <= 1 => {
                Err("No more on-device user device attempts left".to_string())
            }
            UsbState::NeedsPin { .. }
            | UsbState::NeedsUserVerification { .. }
            | UsbState::NeedsUserPresence => {
                match self.usb_uv_handler.check_notification().await? {
                    Some(UsbUvMessage::NeedsPin { attempts_left }) => {
                        Ok(UsbState::NeedsPin { attempts_left })
                    }
                    Some(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                        Ok(UsbState::NeedsUserVerification { attempts_left })
                    }
                    Some(UsbUvMessage::NeedsUserPresence) => Ok(UsbState::NeedsUserPresence),
                    Some(UsbUvMessage::ReceivedCredential(response)) => {
                        match response {
                            AuthenticatorResponse::CredentialCreated(r) => {
                                let mut cred_response = self.cred_response.lock().unwrap();
                                cred_response.replace(
                                    CredentialResponse::CreatePublicKeyCredentialResponse(
                                        MakeCredentialResponseInternal::new(
                                            r,
                                            vec![String::from("usb")],
                                            String::from("cross-platform"),
                                        ),
                                    ),
                                );
                                Ok(UsbState::Completed)
                            }
                            AuthenticatorResponse::CredentialsAsserted(r) => {
                                // at least one credential is returned from the authenticator
                                assert!(!r.assertions.is_empty());
                                if r.assertions.len() == 1 {
                                    let mut cred_response = self.cred_response.lock().unwrap();
                                    cred_response.replace(
                                        CredentialResponse::GetPublicKeyCredentialResponse(
                                            GetAssertionResponseInternal::new(
                                                r.assertions[0].clone(),
                                                String::from("cross-platform"),
                                            ),
                                        ),
                                    );
                                    Ok(UsbState::Completed)
                                } else {
                                    todo!("need to support selection from multiple credentials");
                                }
                            }
                        }
                    }
                    None => Ok(prev_usb_state),
                }
            }
            UsbState::Completed => Ok(prev_usb_state),
        }?;

        *self.usb_state.lock().await = next_usb_state.clone();
        Ok(next_usb_state)
    }

    pub(crate) async fn cancel_device_discovery_usb(&mut self) -> Result<(), String> {
        *self.usb_state.lock().await = UsbState::Idle;
        println!("frontend: Cancel USB request");
        Ok(())
    }

    pub(crate) async fn validate_usb_device_pin(&mut self, pin: &str) -> Result<(), ()> {
        let current_state = self.usb_state.lock().await.clone();
        match current_state {
            UsbState::NeedsPin {
                attempts_left: Some(attempts_left),
            } if attempts_left > 1 => {
                self.usb_uv_handler.send_pin(pin).await;
                Ok(())
            }
            _ => Err(()),
        }
    }

    pub(crate) fn complete_auth(&mut self) {
        // let mut data = self.output_data.lock().unwrap();
        // data.replace((self.cred_response));
    }

    pub(crate) fn get_hybrid_credential(&self) -> HybridStateStream<H::Stream> {
        let stream = self.hybrid_handler.start();
        HybridStateStream {
            inner: stream,
            cred_response: self.cred_response.clone(),
        }
    }
}

pub struct HybridStateStream<H> {
    inner: H,
    cred_response: Arc<Mutex<Option<CredentialResponse>>>,
}

impl<H> Stream for HybridStateStream<H>
where
    H: Stream<Item = HybridState> + Unpin + Sized,
{
    type Item = HybridState;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let cred_response = &self.cred_response.clone();
        match Box::pin(Box::pin(self).as_mut().inner.next()).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(state)) => {
                if let HybridState::Completed(assertion) = &state {
                    let mut cred_response = cred_response.lock().unwrap();
                    cred_response.replace(CredentialResponse::GetPublicKeyCredentialResponse(
                        GetAssertionResponseInternal::new(
                            assertion.clone(),
                            String::from("cross-platform"),
                        ),
                    ));
                }
                Poll::Ready(Some(state))
            }
            Poll::Ready(None) => Poll::Ready(None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// USB device connected, prompt user to tap
    Connected(HidDevice),

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    /// USB tapped, received credential
    Completed,
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice(Vec<HidDevice>),
}

#[derive(Clone, Debug)]
pub struct UsbUvHandler {
    signal_tx: async_std::channel::Sender<Result<UsbUvMessage, String>>,
    signal_rx: async_std::channel::Receiver<Result<UsbUvMessage, String>>,
    pin_tx: async_std::channel::Sender<String>,
    pin_rx: async_std::channel::Receiver<String>,
}

impl UsbUvHandler {
    fn new() -> Self {
        let (signal_tx, signal_rx) = async_std::channel::unbounded();
        let (pin_tx, pin_rx) = async_std::channel::unbounded();
        UsbUvHandler {
            signal_tx,
            signal_rx,
            pin_tx,
            pin_rx,
        }
    }

    async fn notify_ceremony_completed(&self, response: AuthenticatorResponse) {
        self.signal_tx
            .send(Ok(UsbUvMessage::ReceivedCredential(response)))
            .await
            .unwrap();
    }

    async fn notify_ceremony_failed(&self, err: String) {
        self.signal_tx.send(Err(err)).await.unwrap();
    }

    async fn send_pin(&self, pin: &str) {
        self.pin_tx.send(pin.to_owned()).await.unwrap();
    }

    async fn wait_for_notification(&self) -> Result<UsbUvMessage, String> {
        match self.signal_rx.recv().await {
            Ok(msg) => msg,
            Err(err) => Err(err.to_string()),
        }
    }

    async fn check_notification(&self) -> Result<Option<UsbUvMessage>, String> {
        match self.signal_rx.try_recv() {
            Ok(msg) => Ok(Some(msg?)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err("USB UV handler channel closed".to_string()),
        }
    }
}

async fn handle_usb_updates(
    signal_tx: async_std::channel::Sender<Result<UsbUvMessage, String>>,
    pin_rx: async_std::channel::Receiver<String>,
    mut state_rx: tokio::sync::mpsc::Receiver<UxUpdate>,
) {
    while let Some(msg) = state_rx.recv().await {
        match msg {
            UxUpdate::UvRetry { attempts_left } => {
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserVerification { attempts_left }))
                    .await
                    .unwrap();
            }
            UxUpdate::PinRequired(pin_update) => {
                if pin_update.attempts_left.is_some_and(|num| num <= 1) {
                    // TODO: cancel authenticator operation
                    signal_tx.send(Err("No more PIN attempts allowed. Select a different authenticator or try again later.".to_string())).await.unwrap();
                    continue;
                }
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsPin {
                        attempts_left: pin_update.attempts_left,
                    }))
                    .await
                    .unwrap();
                if let Ok(pin) = pin_rx.recv().await {
                    pin_update.send_pin(&pin).unwrap();
                } else {
                    debug!("PIN channel closed.");
                }
            }
            UxUpdate::PresenceRequired => {
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserPresence))
                    .await
                    .unwrap();
            }
        }
    }
    debug!("USB update channel closed.");
}

enum UsbUvMessage {
    NeedsPin { attempts_left: Option<u32> },
    NeedsUserVerification { attempts_left: Option<u32> },
    NeedsUserPresence,
    ReceivedCredential(AuthenticatorResponse),
}
fn tokio() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("Tokio runtime to start"))
}

enum AuthenticatorResponse {
    CredentialCreated(MakeCredentialResponse),
    CredentialsAsserted(GetAssertionResponse),
}

#[cfg(test)]
mod test {
    use std::{
        sync::{Arc, Mutex},
        task::Poll,
    };

    use async_std::stream::{Stream, StreamExt};
    use libwebauthn::ops::webauthn::MakeCredentialRequest;

    use crate::dbus::{
        CreateCredentialRequest, CreatePublicKeyCredentialRequest, CredentialRequest,
    };

    use super::{
        hybrid::{HybridHandlerInternal, HybridState},
        CredentialService, HybridHandler,
    };

    /*
    #[test]
    fn test_hybrid() {
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
        let (req, client_data_json) = CreateCredentialRequest {
            origin: Some("webauthn.io".to_string()),
            is_same_origin: Some(true),
            r#type: "public-key".to_string(),
            public_key: Some(CreatePublicKeyCredentialRequest {
                request_json: request_json,
            }),
        }
        .try_into_ctap2_request()
        .unwrap();
        let request = CredentialRequest::CreatePublicKeyCredentialRequest(req);
        let response = Arc::new(Mutex::new(None));
        let qr_code = String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332");
        // SHA256(webauthn.io) + AUTH_FLAGS(UP | UV) + u32(1)
        #[rustfmt::skip]
        let attestation_object = vec![
            // map(3)
            0xb9, 0x0, 0x3,
            // text(authData)
            0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61,
            // bytes(sha-256(webauthn.io) + AUTH_FLAGS(UP | UV) + signCount(1))
            0x58, 0x25, 0x74, 0xa6, 0xea, 0x92, 0x13, 0xc9, 0x9c, 0x2f, 0x74, 0xb2, 0x24, 0x92,
            0xb3, 0x20, 0xcf, 0x40, 0x26, 0x2a, 0x94, 0xc1, 0xa9, 0x50, 0xa0, 0x39, 0x7f, 0x29,
            0x25, 0xb, 0x60, 0x84, 0x1e, 0xf0, 0x5, 0x0, 0x0, 0x0, 0x1,
            // text(fmt)
            0x63, 0x66, 0x6d, 0x74,
            // text(none)
            0x64, 0x6e, 0x6f, 0x6e, 0x65,
            // text attStmt
            0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74,
            // map(0)
            0xb9, 0x0, 0x0,
        ];

        let hybrid_handler = StaticHybridHandler::new(vec![
            HybridState::Init(qr_code),
            HybridState::Waiting,
            HybridState::Connecting,
            HybridState::Completed(assertion),
        ]);
        let cred_service = CredentialService::new(request, response, hybrid_handler);
        let mut stream = cred_service.hybrid_handler.start();
        async_std::task::block_on(async {
            while let Some(state) = stream.next().await {
                println!("{:?}", state);
            }
        })
    }
    */

    #[derive(Debug)]
    struct StaticHybridHandler {
        states: Vec<HybridState>,
    }

    impl StaticHybridHandler {
        fn new(states: Vec<HybridState>) -> Self {
            Self { states }
        }
    }
    impl HybridHandler for StaticHybridHandler {}

    impl HybridHandlerInternal for StaticHybridHandler {
        type Stream = StaticHybridHandlerStream;
        fn start(&self) -> Self::Stream {
            StaticHybridHandlerStream {
                qr_code: String::from("FIDO:/078241338926040702789239694720083010994762289662861130514766991835876383562063181103169246410435938367110394959927031730060360967994421343201235185697538107096654083332"),
                states: self.states.clone(),
            }
        }
    }

    struct StaticHybridHandlerStream {
        qr_code: String,
        states: Vec<HybridState>,
    }
    impl Stream for StaticHybridHandlerStream {
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
}
