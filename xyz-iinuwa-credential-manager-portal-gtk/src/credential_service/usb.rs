use std::time::Duration;

use async_stream::stream;
use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_lite::Stream;
use libwebauthn::{
    ops::webauthn::GetAssertionResponse,
    transport::{hid::HidDevice, Device},
    webauthn::{Error as WebAuthnError, WebAuthn},
    UxUpdate,
};
use tokio::sync::mpsc::{self, Receiver, Sender, WeakSender};
use tracing::{debug, warn};

use crate::{
    dbus::{CredentialRequest, GetAssertionResponseInternal},
    view_model::Credential,
};

use super::{AuthenticatorResponse, CredentialResponse};

pub(crate) trait UsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static;
}

#[derive(Debug)]
pub struct InProcessUsbHandler {}

impl InProcessUsbHandler {
    async fn process(
        tx: Sender<UsbStateInternal>,
        cred_request: CredentialRequest,
    ) -> Result<(), String> {
        let mut state = UsbStateInternal::Idle;
        let (signal_tx, mut signal_rx) = mpsc::channel(256);
        let (cred_tx, mut cred_rx) = mpsc::channel(1);
        debug!("polling for USB status");
        loop {
            tracing::debug!("current usb state: {:?}", state);
            let prev_usb_state = state;
            let next_usb_state = match prev_usb_state {
                UsbStateInternal::Idle | UsbStateInternal::Waiting => {
                    let mut hid_devices =
                        libwebauthn::transport::hid::list_devices().await.unwrap();
                    if hid_devices.is_empty() {
                        let state = UsbStateInternal::Waiting;
                        Ok(state)
                    } else if hid_devices.len() == 1 {
                        Ok(UsbStateInternal::Connected(hid_devices.swap_remove(0)))
                    } else {
                        Ok(UsbStateInternal::SelectingDevice(hid_devices))
                    }
                }
                UsbStateInternal::SelectingDevice(hid_devices) => {
                    let (blinking_tx, mut blinking_rx) =
                        tokio::sync::mpsc::channel::<Option<HidDevice>>(hid_devices.len());
                    let mut expected_answers = hid_devices.len();
                    for mut device in hid_devices {
                        let tx = blinking_tx.clone();
                        tokio::spawn(async move {
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
                    let mut state = UsbStateInternal::Idle;
                    while let Some(msg) = blinking_rx.recv().await {
                        expected_answers -= 1;
                        match msg {
                            Some(device) => {
                                state = UsbStateInternal::Connected(device);
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
                UsbStateInternal::Connected(device) => {
                    let signal_tx2 = signal_tx.clone();
                    let cred_request = cred_request.clone();
                    tokio::spawn(async move {
                        handle_events(&cred_request, device, &signal_tx2).await;
                    });
                    match signal_rx.recv().await {
                        Some(Ok(UsbUvMessage::NeedsPin {
                            attempts_left,
                            pin_tx,
                        })) => Ok(UsbStateInternal::NeedsPin {
                            attempts_left,
                            pin_tx,
                        }),
                        Some(Ok(UsbUvMessage::NeedsUserVerification { attempts_left })) => {
                            Ok(UsbStateInternal::NeedsUserVerification { attempts_left })
                        }
                        Some(Ok(UsbUvMessage::NeedsUserPresence)) => {
                            Ok(UsbStateInternal::NeedsUserPresence)
                        }
                        Some(Ok(UsbUvMessage::ReceivedCredentials(response))) => match response {
                            AuthenticatorResponse::CredentialCreated(make_credential_response) => {
                                Ok(UsbStateInternal::Completed(
                                    CredentialResponse::from_make_credential(
                                        &make_credential_response,
                                        &["usb"],
                                        "cross-platform",
                                    ),
                                ))
                            }
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
                        Some(Err(err)) => Err(err.clone()),
                        None => Err("Channel disconnected".to_string()),
                    }
                }
                UsbStateInternal::NeedsPin { .. }
                | UsbStateInternal::NeedsUserVerification { .. }
                | UsbStateInternal::NeedsUserPresence => match signal_rx.recv().await {
                    Some(msg) => match msg? {
                        UsbUvMessage::NeedsPin {
                            attempts_left,
                            pin_tx,
                        } => Ok(UsbStateInternal::NeedsPin {
                            attempts_left,
                            pin_tx,
                        }),
                        UsbUvMessage::NeedsUserVerification { attempts_left } => {
                            Ok(UsbStateInternal::NeedsUserVerification { attempts_left })
                        }
                        UsbUvMessage::NeedsUserPresence => Ok(UsbStateInternal::NeedsUserPresence),
                        UsbUvMessage::ReceivedCredentials(response) => match response {
                            AuthenticatorResponse::CredentialCreated(make_credential_response) => {
                                Ok(UsbStateInternal::Completed(
                                    CredentialResponse::from_make_credential(
                                        &make_credential_response,
                                        &["usb"],
                                        "cross-platform",
                                    ),
                                ))
                            }
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
                    },
                    None => Err("USB UV handler channel closed".to_string()),
                },
                UsbStateInternal::Completed(_) => Ok(prev_usb_state),
                UsbStateInternal::SelectCredential {
                    response,
                    cred_tx: _,
                } => match cred_rx.recv().await {
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
                                        URL_SAFE_NO_PAD.encode(ring::digest::digest(
                                            &ring::digest::SHA256,
                                            &c.id,
                                        )) == cred_id
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
                            None => Err("Selected credential not found.".to_string()),
                        }
                    }
                    None => {
                        tracing::debug!("cred channel closed before receiving cred from client.");
                        Err("Cred channel disconnected".to_string())
                    }
                },
            };
            state = next_usb_state?;
            tx.send(state.clone())
                .await
                .map_err(|_| "Receiver channel closed".to_string())?;
            if let UsbStateInternal::Completed(_) = state {
                break Ok(());
            }
        }
    }
}

async fn handle_events(
    cred_request: &CredentialRequest,
    mut device: HidDevice,
    signal_tx: &Sender<Result<UsbUvMessage, String>>,
) {
    let (mut channel, state_rx) = device.channel().await.unwrap();
    let signal_tx2 = signal_tx.clone().downgrade();
    tokio::spawn(async move {
        handle_usb_updates(&signal_tx2, state_rx).await;
        debug!("Reached end of USB update task");
    });
    match cred_request {
        CredentialRequest::CreatePublicKeyCredentialRequest(make_cred_request) => loop {
            match channel.webauthn_make_credential(make_cred_request).await {
                Ok(response) => {
                    notify_ceremony_completed(
                        signal_tx,
                        AuthenticatorResponse::CredentialCreated(response),
                    )
                    .await;
                    break;
                }
                Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                    warn!("Retrying WebAuthn make credential operation");
                    continue;
                }
                Err(err) => {
                    notify_ceremony_failed(signal_tx, err.to_string()).await;
                    break;
                }
            };
        },
        CredentialRequest::GetPublicKeyCredentialRequest(get_cred_request) => loop {
            match channel.webauthn_get_assertion(get_cred_request).await {
                Ok(response) => {
                    notify_ceremony_completed(
                        signal_tx,
                        AuthenticatorResponse::CredentialsAsserted(response),
                    )
                    .await;
                    break;
                }
                Err(WebAuthnError::Ctap(ctap_error)) if ctap_error.is_retryable_user_error() => {
                    warn!("Retrying WebAuthn get credential operation");
                    continue;
                }
                Err(err) => {
                    notify_ceremony_failed(signal_tx, err.to_string()).await;
                    break;
                }
            };
        },
    };
}

async fn notify_ceremony_completed(
    signal_tx: &Sender<Result<UsbUvMessage, String>>,
    response: AuthenticatorResponse,
) {
    signal_tx
        .send(Ok(UsbUvMessage::ReceivedCredentials(response)))
        .await
        .unwrap();
}

async fn notify_ceremony_failed(signal_tx: &Sender<Result<UsbUvMessage, String>>, err: String) {
    signal_tx.send(Err(err)).await.unwrap();
}

impl UsbHandler for InProcessUsbHandler {
    fn start(
        &self,
        request: &CredentialRequest,
    ) -> impl Stream<Item = UsbEvent> + Send + Sized + Unpin + 'static {
        let request = request.clone();
        let (tx, mut rx) = mpsc::channel(32);
        tokio::spawn(async move {
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

pub struct UsbEvent {
    pub(super) state: UsbStateInternal,
}

#[derive(Clone, Debug, Default)]
pub(super) enum UsbStateInternal {
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
        pin_tx: mpsc::Sender<String>,
    },

    /// The device needs on-device user verification.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs evidence of user presence (e.g. touch) to release the credential.
    NeedsUserPresence,

    // Multiple credentials have been found and the user has to select which to use
    SelectCredential {
        response: GetAssertionResponse,
        cred_tx: mpsc::Sender<String>,
    },

    /// USB tapped, received credential
    Completed(CredentialResponse),
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice(Vec<HidDevice>),
}

#[derive(Clone, Debug, Default)]
pub enum UsbState {
    /// Not polling for FIDO USB device.
    #[default]
    Idle,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

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

    /// USB tapped, received credential
    Completed,
    // TODO: implement cancellation
    // This isn't actually sent from the server.
    //UserCancelled,

    // When we encounter multiple devices, we let all of them blink and continue
    // with the one that was tapped.
    SelectingDevice,

    // Multiple credentials have been found and the user has to select which to use
    // List of user-identities to decide which to use.
    SelectCredential {
        creds: Vec<Credential>,
        cred_tx: mpsc::Sender<String>,
    },
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
        }
    }
}

async fn handle_usb_updates(
    signal_tx: &WeakSender<Result<UsbUvMessage, String>>,
    mut state_rx: Receiver<UxUpdate>,
) {
    while let Some(msg) = state_rx.recv().await {
        let signal_tx = match signal_tx.upgrade() {
            Some(tx) => tx,
            None => break,
        };
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
                let (pin_tx, mut pin_rx) = mpsc::channel(1);
                signal_tx
                    .send(Ok(UsbUvMessage::NeedsPin {
                        pin_tx,
                        attempts_left: pin_update.attempts_left,
                    }))
                    .await
                    .unwrap();
                match pin_rx.recv().await {
                    Some(pin) => match pin_update.send_pin(&pin) {
                        Ok(()) => {}
                        Err(err) => tracing::error!("Error sending pin to device: {:?}", err),
                    },
                    None => tracing::debug!("Pin channel closed before receiving pin from client."),
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
