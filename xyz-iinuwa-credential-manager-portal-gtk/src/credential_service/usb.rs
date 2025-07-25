use std::{collections::HashMap, time::Duration};

use async_stream::stream;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_lite::Stream;
use libwebauthn::{
    ops::webauthn::GetAssertionResponse,
    proto::CtapError,
    transport::{
        hid::{channel::HidChannelHandle, HidDevice},
        Channel, Device,
    },
    webauthn::{Error as WebAuthnError, WebAuthn},
    UvUpdate,
};
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender, WeakSender};
use tracing::{debug, warn};

use crate::{
    dbus::{CredentialRequest, GetAssertionResponseInternal},
    gui::view_model::Credential,
};

use super::{AuthenticatorResponse, CredentialResponse, Error};

pub(crate) trait UsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static;
}

#[derive(Debug)]
pub struct InProcessUsbHandler {}

impl InProcessUsbHandler {
    async fn process_idle_waiting(
        failures: &mut usize,
        prev_usb_state: &UsbStateInternal,
    ) -> Result<UsbStateInternal, Error> {
        match libwebauthn::transport::hid::list_devices().await {
            Ok(mut hid_devices) => {
                if hid_devices.is_empty() {
                    let state = UsbStateInternal::Waiting;
                    Ok(state)
                } else if hid_devices.len() == 1 {
                    Ok(UsbStateInternal::Connected(hid_devices.swap_remove(0)))
                } else {
                    Ok(UsbStateInternal::SelectingDevice(hid_devices))
                }
            }
            Err(err) => {
                *failures += 1;
                if *failures == 5 {
                    Err(Error::Internal(format!(
                        "Failed to list USB authenticators: {:?}. Cancelling USB state updates.",
                        err
                    )))
                } else {
                    tracing::warn!(
                        "Failed to list USB authenticators: {:?}. Throttling USB state updates",
                        err
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(prev_usb_state.clone())
                }
            }
        }
    }

    async fn process_selecting_device(
        hid_devices: Vec<HidDevice>,
    ) -> Result<UsbStateInternal, Error> {
        let expected_answers = hid_devices.len();
        let (blinking_tx, mut blinking_rx) =
            tokio::sync::mpsc::channel::<Option<usize>>(expected_answers);
        let mut channel_map = HashMap::new();
        let (setup_tx, mut setup_rx) =
            tokio::sync::mpsc::channel::<(usize, HidDevice, HidChannelHandle)>(expected_answers);
        for (idx, mut device) in hid_devices.into_iter().enumerate() {
            let stx = setup_tx.clone();
            let tx = blinking_tx.clone();
            tokio::spawn(async move {
                let dev = device.clone();

                let res = match device.channel().await {
                    Ok(ref mut channel) => {
                        let cancel_handle = channel.get_handle();
                        stx.send((idx, dev, cancel_handle)).await.unwrap();
                        drop(stx);

                        let was_selected = channel
                            .blink_and_wait_for_user_presence(Duration::from_secs(300))
                            .await;
                        match was_selected {
                            Ok(true) => Ok(Some(idx)),
                            Ok(false) => Ok(None),
                            Err(err) => Err(format!(
                                "Failed to send wink request to authenticator: {:?}",
                                err
                            )),
                        }
                    }
                    Err(err) => Err(format!(
                        "Failed to create channel for USB authenticator: {:?}",
                        err
                    )),
                }
                .inspect_err(|err| tracing::warn!(err))
                .unwrap_or_default(); // In case of error, we also send `None`
                if let Err(err) = tx.send(res).await {
                    tracing::error!("Failed to send notification of wink response: {:?}", err,);
                }
            });
        }
        drop(setup_tx);
        // Receiving all cancel handles
        while let Some((idx, device, handle)) = setup_rx.recv().await {
            channel_map.insert(idx, (device, handle));
        }

        tracing::info!("Waiting for user interaction");
        drop(blinking_tx);
        let mut state = UsbStateInternal::Idle;
        while let Some(msg) = blinking_rx.recv().await {
            match msg {
                Some(idx) => {
                    let (device, _handle) = channel_map.remove(&idx).unwrap();
                    tracing::info!("User selected device {device:?}.");
                    for (_key, (device, handle)) in channel_map.into_iter() {
                        tracing::info!("Cancelling device {device:?}.");
                        handle.cancel_ongoing_operation().await;
                    }
                    state = UsbStateInternal::Connected(device);
                    break;
                }
                None => {
                    continue;
                }
            }
        }
        Ok(state)
    }

    async fn process_select_credential(
        response: GetAssertionResponse,
        cred_rx: &mut Receiver<String>,
    ) -> Result<UsbStateInternal, Error> {
        match cred_rx.recv().await {
            Some(cred_id) => {
                let assertion = response
                    .assertions
                    .iter()
                    .find(|c| {
                        c.credential_id
                            .as_ref()
                            .map(|c| {
                                // In order to not expose the credential ID to the untrusted UI component,
                                // we hashed it, before sending it. So we have to re-hash all our credential
                                // IDs to identify the selected one.
                                URL_SAFE_NO_PAD
                                    .encode(ring::digest::digest(&ring::digest::SHA256, &c.id))
                                    == cred_id
                            })
                            .unwrap_or_default()
                    })
                    .cloned();
                match assertion {
                    Some(assertion) => Ok(UsbStateInternal::Completed(
                        CredentialResponse::GetPublicKeyCredentialResponse(
                            GetAssertionResponseInternal::new(
                                assertion,
                                "cross-platform".to_string(),
                            ),
                        ),
                    )),
                    None => Err(Error::NoCredentials),
                }
            }
            None => {
                tracing::debug!("cred channel closed before receiving cred from client.");
                Err(Error::Internal(
                    "Cred channel disconnected prematurely".to_string(),
                ))
            }
        }
    }

    async fn process_user_interaction(
        signal_rx: &mut Receiver<Result<UsbUvMessage, Error>>,
        cred_tx: &Sender<String>,
    ) -> Result<UsbStateInternal, Error> {
        match signal_rx.recv().await {
            Some(msg) => match msg {
                Ok(UsbUvMessage::NeedsPin {
                    attempts_left,
                    pin_tx,
                }) => Ok(UsbStateInternal::NeedsPin {
                    attempts_left,
                    pin_tx,
                }),
                Ok(UsbUvMessage::NeedsUserVerification { attempts_left }) => {
                    Ok(UsbStateInternal::NeedsUserVerification { attempts_left })
                }
                Ok(UsbUvMessage::NeedsUserPresence) => Ok(UsbStateInternal::NeedsUserPresence),
                Ok(UsbUvMessage::ReceivedCredentials(response)) => match response {
                    AuthenticatorResponse::CredentialCreated(make_credential_response) => Ok(
                        UsbStateInternal::Completed(CredentialResponse::from_make_credential(
                            &make_credential_response,
                            &["usb"],
                            "cross-platform",
                        )),
                    ),
                    AuthenticatorResponse::CredentialsAsserted(get_assertion_response) => {
                        if get_assertion_response.assertions.len() == 1 {
                            Ok(UsbStateInternal::Completed(
                                CredentialResponse::from_get_assertion(
                                    &get_assertion_response.assertions[0],
                                    "cross-platform",
                                ),
                            ))
                        } else {
                            Ok(UsbStateInternal::SelectCredential {
                                response: get_assertion_response,
                                cred_tx: cred_tx.clone(),
                            })
                        }
                    }
                },
                Err(err) => Err(err),
            },
            None => Err(Error::Internal("USB UV handler channel closed".to_string())),
        }
    }

    async fn process(
        tx: Sender<UsbStateInternal>,
        cred_request: CredentialRequest,
    ) -> Result<(), Error> {
        let mut state = UsbStateInternal::Idle;
        let (signal_tx, mut signal_rx) = mpsc::channel(256);
        let (cred_tx, mut cred_rx) = mpsc::channel(1);
        debug!("polling for USB status");
        let mut failures = 0;
        // act on current USB USB state, send state changes to the stream, and
        // loop until a credential or error is returned.
        loop {
            tracing::debug!("current usb state: {:?}", state);
            let prev_usb_state = state;
            let next_usb_state = match prev_usb_state {
                UsbStateInternal::Idle | UsbStateInternal::Waiting => {
                    Self::process_idle_waiting(&mut failures, &prev_usb_state).await
                }
                UsbStateInternal::SelectingDevice(hid_devices) => {
                    Self::process_selecting_device(hid_devices).await
                }
                UsbStateInternal::Connected(device) => {
                    let signal_tx2 = signal_tx.clone();
                    let cred_request = cred_request.clone();
                    tokio::spawn(async move {
                        handle_events(&cred_request, device, &signal_tx2).await;
                    });
                    Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                }
                UsbStateInternal::NeedsPin { .. }
                | UsbStateInternal::NeedsUserVerification { .. }
                | UsbStateInternal::NeedsUserPresence => {
                    Self::process_user_interaction(&mut signal_rx, &cred_tx).await
                }
                UsbStateInternal::SelectCredential {
                    response,
                    cred_tx: _,
                } => Self::process_select_credential(response, &mut cred_rx).await,
                UsbStateInternal::Completed(_) => break Ok(()),
                UsbStateInternal::Failed(err) => break Err(err),
            };
            state = next_usb_state.unwrap_or_else(UsbStateInternal::Failed);
            tx.send(state.clone()).await.map_err(|_| {
                Error::Internal("USB state channel receiver closed prematurely".to_string())
            })?;
        }
    }
}

async fn handle_events(
    cred_request: &CredentialRequest,
    mut device: HidDevice,
    signal_tx: &Sender<Result<UsbUvMessage, Error>>,
) {
    let device_debug = device.to_string();
    match device.channel().await {
        Err(err) => {
            tracing::error!("Failed to open channel to USB authenticator, cannot receive user verification events: {:?}", err);
        }
        Ok(mut channel) => {
            let signal_tx2 = signal_tx.clone().downgrade();
            let ux_updates_rx = channel.get_ux_update_receiver();
            tokio::spawn(async move {
                handle_usb_updates(&signal_tx2, ux_updates_rx).await;
                debug!("Reached end of USB update task");
            });
            tracing::debug!(
                "Polling for credential from USB authenticator {}",
                &device_debug
            );
            let response: Result<UsbUvMessage, Error> = loop {
                let response = match cred_request {
                    CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => {
                        channel
                            .webauthn_make_credential(make_cred_request)
                            .await
                            .map(|response| UsbUvMessage::ReceivedCredentials(response.into()))
                    }
                    CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => channel
                        .webauthn_get_assertion(get_cred_request)
                        .await
                        .map(|response| UsbUvMessage::ReceivedCredentials(response.into())),
                };
                match response {
                    Ok(response) => {
                        tracing::debug!("Received credential from USB authenticator");
                        break Ok(response);
                    }
                    Err(WebAuthnError::Ctap(ctap_error))
                        if ctap_error.is_retryable_user_error() =>
                    {
                        warn!("Retrying WebAuthn credential operation");
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to make/get credential with USB authenticator: {:?}",
                            err
                        );
                        break Err(err);
                    }
                }
            }
            .map_err(|err| match err {
                WebAuthnError::Ctap(CtapError::PINAuthBlocked) => Error::PinAttemptsExhausted,
                WebAuthnError::Ctap(CtapError::NoCredentials) => Error::NoCredentials,
                _ => Error::AuthenticatorError,
            });
            if let Err(err) = signal_tx.send(response).await {
                tracing::error!("Failed to notify that ceremony completed: {:?}", err);
            }
        }
    }
}

impl UsbHandler for InProcessUsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(32);
        tokio::spawn(async move {
            // TODO: instead of logging error here, push the errors into the
            // stream so credential service can handle/forward them to the UI
            if let Err(err) = InProcessUsbHandler::process(tx, request).await {
                tracing::error!("Error getting credential from USB: {:?}", err);
            }
        });
        Box::pin(stream! {
            while let Some(state) = rx.recv().await {
                yield UsbEvent { state }
            }
        })
    }
}

// this exists to prevent making UsbStateInternal type public to the whole crate.
/// A message between USB handler and credential service
pub struct UsbEvent {
    pub(super) state: UsbStateInternal,
}

/// Used to share internal state between handler and credential service
#[derive(Clone, Debug, Default)]
pub(super) enum UsbStateInternal {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// When we encounter multiple devices, we let all of them blink and continue
    /// with the one that was tapped.
    SelectingDevice(Vec<HidDevice>),

    /// USB device connected, prompt user to tap
    Connected(HidDevice),

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification { attempts_left: Option<u32> },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    /// Multiple credentials have been found and the user has to select which to use
    SelectCredential {
        response: GetAssertionResponse,
        cred_tx: mpsc::Sender<String>,
    },

    /// USB tapped, received credential
    Completed(CredentialResponse),

    /// There was an error while interacting with the authenticator.
    Failed(Error),
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,
}

/// Used to share public state between  credential service and UI.
#[derive(Clone, Debug, Default)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice,

    /// USB device connected, prompt user to tap
    Connected,

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },

    /// USB tapped, received credential
    Completed,

    /// Interaction with the authenticator failed.
    Failed(Error),
}

impl From<UsbStateInternal> for UsbState {
    fn from(value: UsbStateInternal) -> Self {
        match value {
            UsbStateInternal::Idle => UsbState::Idle,
            UsbStateInternal::Waiting => UsbState::Waiting,
            UsbStateInternal::Connected(_) => UsbState::Connected,
            UsbStateInternal::NeedsPin {
                attempts_left,
                pin_tx,
            } => UsbState::NeedsPin {
                attempts_left,
                pin_tx,
            },
            UsbStateInternal::NeedsUserVerification { attempts_left } => {
                UsbState::NeedsUserVerification { attempts_left }
            }
            UsbStateInternal::NeedsUserPresence => UsbState::NeedsUserPresence,
            UsbStateInternal::Completed(_) => UsbState::Completed,
            // UsbStateInternal::UserCancelled => UsbState:://UserCancelled,
            UsbStateInternal::SelectingDevice(_) => UsbState::SelectingDevice,
            UsbStateInternal::SelectCredential { response, cred_tx } => {
                UsbState::SelectCredential {
                    creds: response
                        .assertions
                        .iter()
                        .map(|x| Credential {
                            id: x
                                .credential_id
                                .as_ref()
                                .map(|i| {
                                    // In order to not expose the credential ID to the untrusted UI components,
                                    // we hash and then encode it into a String.
                                    URL_SAFE_NO_PAD
                                        .encode(ring::digest::digest(&ring::digest::SHA256, &i.id))
                                })
                                .unwrap(),

                            name: x
                                .user
                                .as_ref()
                                .and_then(|u| u.name.clone())
                                .unwrap_or_else(|| String::from("<unknown>")),
                            username: x
                                .user
                                .as_ref()
                                .map(|u| u.display_name.clone())
                                .unwrap_or_default(),
                        })
                        .collect(),
                    cred_tx,
                }
            }
            UsbStateInternal::Failed(err) => UsbState::Failed(err),
        }
    }
}

async fn handle_usb_updates(
    signal_tx: &WeakSender<Result<UsbUvMessage, Error>>,
    mut state_rx: broadcast::Receiver<UvUpdate>,
) {
    while let Ok(msg) = state_rx.recv().await {
        let signal_tx = match signal_tx.upgrade() {
            Some(tx) => tx,
            None => break,
        };
        match msg {
            UvUpdate::UvRetry { attempts_left } => {
                if let Err(err) = signal_tx
                    .send(Ok(UsbUvMessage::NeedsUserVerification { attempts_left }))
                    .await
                {
                    tracing::error!("Authenticator requested user verficiation, but we cannot relay the message to credential service: {:?}", err);
                }
            }
            UvUpdate::PinRequired(pin_update) => {
                let (pin_tx, mut pin_rx) = mpsc::channel(1);
                if let Err(err) = signal_tx
                    .send(Ok(UsbUvMessage::NeedsPin {
                        pin_tx,
                        attempts_left: pin_update.attempts_left,
                    }))
                    .await
                {
                    tracing::error!("Authenticator requested a PIN from the user, but we cannot relay the message to the credential service: {:?}", err);
                }
                match pin_rx.recv().await {
                    Some(pin) => match pin_update.send_pin(&pin) {
                        Ok(()) => {}
                        Err(err) => tracing::error!("Error sending pin to device: {:?}", err),
                    },
                    None => tracing::debug!("Pin channel closed before receiving pin from client."),
                }
            }
            UvUpdate::PresenceRequired => {
                if let Err(err) = signal_tx.send(Ok(UsbUvMessage::NeedsUserPresence)).await {
                    tracing::error!("Authenticator requested user presence, but we cannot relay the message to the credential service: {:?}", err);
                }
            }
        }
    }
    debug!("USB update channel closed.");
}

/// Messages sent between USB authenticator and handler for UV
enum UsbUvMessage {
    NeedsPin {
        attempts_left: Option<u32>,
        pin_tx: mpsc::Sender<String>,
    },
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },
    NeedsUserPresence,
    ReceivedCredentials(AuthenticatorResponse),
}
