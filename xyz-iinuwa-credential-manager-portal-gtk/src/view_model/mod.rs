pub mod gtk;

use std::sync::Arc;
use std::time::Duration;

use async_std::prelude::*;
use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex,
};
use tracing::info;

use crate::credential_service::hybrid::DummyHybridHandler;
use crate::credential_service::CredentialService;

#[derive(Debug)]
pub(crate) struct ViewModel {
    credential_service: Arc<Mutex<CredentialService<DummyHybridHandler>>>,
    tx_update: Sender<ViewUpdate>,
    rx_event: Receiver<ViewEvent>,
    bg_update: Sender<BackgroundEvent>,
    bg_event: Receiver<BackgroundEvent>,
    title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Option<Device>,
    selected_credential: Option<String>,

    providers: Vec<Provider>,

    usb_device_state: UsbState,
    usb_device_pin_state: UsbPinState,

    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Option<Vec<u8>>,

    hybrid_linked_state: HybridState,
}

impl ViewModel {
    pub(crate) fn new(
        operation: Operation,
        credential_service: CredentialService<DummyHybridHandler>,
        rx_event: Receiver<ViewEvent>,
        tx_update: Sender<ViewUpdate>,
    ) -> Self {
        let (bg_update, bg_event) = async_std::channel::unbounded::<BackgroundEvent>();
        Self {
            credential_service: Arc::new(Mutex::new(credential_service)),
            rx_event,
            tx_update,
            bg_update,
            bg_event,
            operation,
            title: String::default(),
            devices: Vec::new(),
            selected_device: None,
            selected_credential: None,
            providers: Vec::new(),
            usb_device_state: UsbState::default(),
            usb_device_pin_state: UsbPinState::default(),
            hybrid_qr_state: HybridState::default(),
            hybrid_qr_code_data: None,
            hybrid_linked_state: HybridState::default(),
        }
    }
    fn start_authentication(&self) {} // open page
    fn cancel_authentication(&self) {}

    fn start_fingerprint_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_fingerprint_authentication(&self) {}

    fn start_hybrid_qr_authentication(&self) {}
    fn cancel_hybrid_qr_authentication(&self) {
        todo!("not implemented");
    }

    fn start_hybrid_linked_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_hybrid_linked_authentication(&self) {
        todo!("not implemented");
    }

    // Can this be used for internal uv method too?
    fn start_usb_authentication(&self) {
        todo!("not implemented");
    }
    fn cancel_usb_authentication(&self) {
        todo!("not implemented");
    }
    fn send_usb_device_pin(&self) {
        todo!("not implemented");
    }

    fn select_uv_method(&self) {
        todo!("not implemented");
    }

    fn finish_authentication(&self) {
        todo!("not implemented");
    }

    async fn update_title(&mut self) {
        self.title = match self.operation {
            Operation::Create { .. } => "Create new credential",
            Operation::Get { .. } => "Use a credential",
        }
        .to_string();
        self.tx_update
            .send(ViewUpdate::SetTitle(self.title.to_string()))
            .await
            .unwrap();
    }

    async fn update_devices(&mut self) {
        let devices = self
            .credential_service
            .lock()
            .await
            .get_available_public_key_devices()
            .await
            .unwrap();
        self.devices = devices;
        self.tx_update
            .send(ViewUpdate::SetDevices(self.devices.to_owned()))
            .await
            .unwrap();
    }

    pub(crate) async fn select_device(&mut self, id: &str) {
        let device = self.devices.iter().find(|d| d.id == id).unwrap();
        println!("{:?}", device);

        // Handle previous device
        if let Some(prev_device) = self.selected_device.replace(device.clone()) {
            if *device == prev_device {
                return;
            }
            match prev_device.transport {
                Transport::Usb => self
                    .credential_service
                    .lock()
                    .await
                    .cancel_device_discovery_usb()
                    .await
                    .unwrap(),
                Transport::HybridQr => {
                    todo!("Implement cancellation for Hybrid QR");
                }
                _ => {
                    todo!()
                }
            };
            self.selected_credential = None;
        }

        // start discovery for newly selected device
        match device.transport {
            Transport::Usb => {
                let cred_service = self.credential_service.clone();
                let tx = self.bg_update.clone();
                async_std::task::spawn(async move {
                    // TODO: add cancellation
                    let mut prev_state = UsbState::default();
                    loop {
                        match cred_service.lock().await.poll_device_discovery_usb().await {
                            Ok(usb_state) => {
                                let state = usb_state.into();
                                if prev_state != state {
                                    println!("{:?}", state);
                                    tx.send(BackgroundEvent::UsbStateChanged(state.clone()))
                                        .await
                                        .unwrap();
                                }
                                prev_state = state;
                                match prev_state {
                                    UsbState::Completed => break,
                                    UsbState::UserCancelled => break,
                                    _ => {}
                                };
                                async_std::task::sleep(Duration::from_millis(50)).await;
                            }
                            Err(err) => {
                                // TODO: move to error page
                                tracing::error!(
                                    "There was an error trying to get credentials from USB: {}",
                                    err
                                );
                                break;
                            }
                        };
                    }
                });
            }
            Transport::HybridQr => {
                let tx = self.bg_update.clone();
                let cred_service = self.credential_service.clone();
                let mut stream = cred_service.lock().await.get_hybrid_credential();
                async_std::task::spawn(async move {
                    while let Some(state) = stream.next().await {
                        let state = state.into();
                        match state {
                            HybridState::Idle => {}
                            HybridState::Started(_) => {
                                tx.send(BackgroundEvent::HybridQrStateChanged(state))
                                    .await
                                    .unwrap();
                            }
                            HybridState::Waiting => {
                                tx.send(BackgroundEvent::HybridQrStateChanged(state))
                                    .await
                                    .unwrap();
                            }
                            HybridState::Connecting => {
                                tx.send(BackgroundEvent::HybridQrStateChanged(state))
                                    .await
                                    .unwrap();
                            }
                            HybridState::Completed => {
                                tx.send(BackgroundEvent::HybridQrStateChanged(state))
                                    .await
                                    .unwrap();
                            }
                            HybridState::UserCancelled => break,
                        };
                        async_std::task::sleep(Duration::from_secs(2)).await;
                    }
                    tracing::debug!("Broke out of hybrid QR state stream");
                });
            }
            _ => {
                todo!()
            }
        }

        self.tx_update
            .send(ViewUpdate::WaitingForDevice(device.clone()))
            .await
            .unwrap();
    }

    pub(crate) async fn start_event_loop(&mut self) {
        let view_events = self.rx_event.clone().map(Event::View);
        let bg_events = self.bg_event.clone().map(Event::Background);
        let mut all_events = view_events.merge(bg_events);
        while let Some(event) = all_events.next().await {
            match event {
                Event::View(ViewEvent::Initiated) => {
                    self.update_title().await;
                    self.update_devices().await;
                }
                Event::View(ViewEvent::ButtonClicked) => {
                    println!("Got it!")
                }
                Event::View(ViewEvent::DeviceSelected(id)) => {
                    self.select_device(&id).await;
                    println!("Selected device {id}");
                }
                Event::View(ViewEvent::UsbPinEntered(pin)) => {
                    self.credential_service
                        .lock()
                        .await
                        .validate_usb_device_pin(&pin)
                        .await
                        .unwrap();
                }
                Event::View(ViewEvent::CredentialSelected(cred_id)) => {
                    println!(
                        "Credential selected: {:?}. Current Device: {:?}",
                        cred_id, self.selected_device
                    );
                    self.selected_credential = Some(cred_id.clone());
                    self.tx_update
                        .send(ViewUpdate::SelectCredential(cred_id))
                        .await
                        .unwrap();
                }

                Event::Background(BackgroundEvent::UsbPressed) => {
                    println!("UsbPressed");
                }
                Event::Background(BackgroundEvent::UsbStateChanged(state)) => {
                    self.usb_device_state = state;
                    match self.usb_device_state {
                        UsbState::Connected => {
                            info!("Found USB device")
                        }

                        UsbState::NeedsPin { attempts_left } => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsPin { attempts_left })
                                .await
                                .unwrap();
                        }
                        UsbState::NeedsUserVerification { attempts_left } => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsUserVerification { attempts_left })
                                .await
                                .unwrap();
                        }
                        UsbState::NeedsUserPresence => {
                            self.tx_update
                                .send(ViewUpdate::UsbNeedsUserPresence)
                                .await
                                .unwrap();
                        }
                        UsbState::Completed => {
                            self.credential_service.lock().await.complete_auth();
                            self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                        }
                        UsbState::SelectingDevice => {
                            self.tx_update
                                .send(ViewUpdate::SelectingDevice)
                                .await
                                .unwrap();
                        }
                        UsbState::NotListening | UsbState::Waiting | UsbState::UserCancelled => {}
                    }
                }
                Event::Background(BackgroundEvent::HybridQrStateChanged(state)) => {
                    self.hybrid_qr_state = state.clone();
                    tracing::debug!("Received HybridQrState::{:?}", &state);
                    match state {
                        HybridState::Idle => {
                            self.hybrid_qr_code_data = None;
                        }
                        HybridState::Started(qr_code) => {
                            self.hybrid_qr_code_data = Some(qr_code.clone().into_bytes());
                            self.tx_update
                                .send(ViewUpdate::HybridNeedsQrCode(qr_code))
                                .await
                                .unwrap();
                        }
                        HybridState::Waiting => {}
                        HybridState::Connecting => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update
                                .send(ViewUpdate::HybridConnecting)
                                .await
                                .unwrap();
                        }
                        HybridState::Completed => {
                            self.hybrid_qr_code_data = None;
                            self.credential_service.lock().await.complete_auth();
                            self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                        }
                        HybridState::UserCancelled => {
                            self.hybrid_qr_code_data = None;
                        }
                    };
                }
            };
        }
    }
}

pub enum ViewEvent {
    Initiated,
    ButtonClicked,
    DeviceSelected(String),
    CredentialSelected(String),
    UsbPinEntered(String),
}

pub enum ViewUpdate {
    SetTitle(String),
    SetDevices(Vec<Device>),
    SetCredentials(Vec<Credential>),
    WaitingForDevice(Device),
    SelectCredential(String),
    UsbNeedsPin { attempts_left: Option<u32> },
    UsbNeedsUserVerification { attempts_left: Option<u32> },
    UsbNeedsUserPresence,
    Completed,
    SelectingDevice,

    HybridNeedsQrCode(String),
    HybridConnecting,
}

pub enum BackgroundEvent {
    UsbPressed,
    UsbStateChanged(UsbState),
    HybridQrStateChanged(HybridState),
}

pub enum Event {
    Background(BackgroundEvent),
    View(ViewEvent),
}

#[derive(Clone, Debug, Default)]
pub struct Credential {
    id: String,
    name: String,
    username: Option<String>,
}

#[derive(Debug, Default)]
pub enum FingerprintSensorState {
    #[default]
    Idle,
}

#[derive(Debug)]
pub enum CredentialType {
    Passkey,
    Password,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub id: String,
    pub transport: Transport,
}

#[derive(Clone, Debug, Default)]
pub enum HybridState {
    /// Default state, not listening for hybrid transport.
    #[default]
    Idle,

    /// QR code flow is starting
    Started(String),

    /// QR code is being displayed, awaiting QR code scan and BLE advert from phone.
    Waiting,

    /// BLE advert received, connecting to caBLE tunnel with shared secret.
    Connecting,

    /*  I don't think is necessary to signal.
       /// Connected to device via caBLE tunnel.
       Connected,
    */
    /// Credential received over tunnel.
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,
}

impl From<crate::credential_service::hybrid::HybridState> for HybridState {
    fn from(value: crate::credential_service::hybrid::HybridState) -> Self {
        match value {
            crate::credential_service::hybrid::HybridState::Init(qr_code) => {
                HybridState::Started(qr_code)
            }
            crate::credential_service::hybrid::HybridState::Waiting => HybridState::Waiting,
            crate::credential_service::hybrid::HybridState::Connecting => HybridState::Connecting,
            crate::credential_service::hybrid::HybridState::Completed(_) => HybridState::Completed,
            crate::credential_service::hybrid::HybridState::UserCancelled => {
                HybridState::UserCancelled
            }
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    Create { cred_type: CredentialType },
    Get { cred_types: Vec<CredentialType> },
}

#[derive(Debug, Default)]
pub struct Provider;

#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    Ble,
    HybridLinked,
    HybridQr,
    Internal,
    Nfc,
    Usb,
}

pub enum Error {
    ConversionError,
}

impl TryInto<Transport> for String {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        let value: &str = self.as_ref();
        value.try_into()
    }
}

impl TryInto<Transport> for &str {
    type Error = String;

    fn try_into(self) -> Result<Transport, String> {
        match self {
            "BLE" => Ok(Transport::Ble),
            "HybridLinked" => Ok(Transport::HybridLinked),
            "HybridQr" => Ok(Transport::HybridQr),
            "Internal" => Ok(Transport::Internal),
            "NFC" => Ok(Transport::Nfc),
            "USB" => Ok(Transport::Usb),
            _ => Err(format!("Unrecognized transport: {}", self.to_owned())),
        }
    }
}

impl From<Transport> for String {
    fn from(val: Transport) -> Self {
        val.as_str().to_string()
    }
}

impl Transport {
    fn as_str(&self) -> &'static str {
        match self {
            Transport::Ble => "BLE",
            Transport::HybridLinked => "HybridLinked",
            Transport::HybridQr => "HybridQr",
            Transport::Internal => "Internal",
            Transport::Nfc => "NFC",
            Transport::Usb => "USB",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum UsbState {
    /// Not currently listening for USB devices.
    #[default]
    NotListening,

    /// Awaiting FIDO USB device to be plugged in.
    Waiting,

    /// The device needs the PIN to be entered.
    NeedsPin {
        attempts_left: Option<u32>,
    },

    /// The device needs on-device user verification to be entered.
    NeedsUserVerification {
        attempts_left: Option<u32>,
    },

    /// The device needs on-device user verification to be entered.
    NeedsUserPresence,

    /// USB device connected, prompt user to tap
    Connected,

    /// USB tapped, received credential
    Completed,

    // This isn't actually sent from the server.
    UserCancelled,

    /// Multiple devices found
    SelectingDevice,
}

impl From<crate::credential_service::UsbState> for UsbState {
    fn from(val: crate::credential_service::UsbState) -> Self {
        match val {
            crate::credential_service::UsbState::Idle => UsbState::NotListening,
            crate::credential_service::UsbState::SelectingDevice(..) => UsbState::SelectingDevice,
            crate::credential_service::UsbState::Waiting => UsbState::Waiting,
            crate::credential_service::UsbState::Connected(..) => UsbState::Connected,
            crate::credential_service::UsbState::NeedsPin { attempts_left } => {
                UsbState::NeedsPin { attempts_left }
            }
            crate::credential_service::UsbState::NeedsUserVerification { attempts_left } => {
                UsbState::NeedsUserVerification { attempts_left }
            }
            crate::credential_service::UsbState::NeedsUserPresence => UsbState::NeedsUserPresence,
            crate::credential_service::UsbState::Completed => UsbState::Completed,
        }
    }
}

#[derive(Debug, Default)]
pub enum UsbPinState {
    #[default]
    Waiting,

    PinIncorrect {
        attempts_left: u32,
    },

    LockedOut {
        unlock_time: Duration,
    },

    PinCorrect,
}

#[derive(Debug, Default)]
pub struct UserVerificationMethod;
