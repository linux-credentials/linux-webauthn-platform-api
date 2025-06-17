pub mod gtk;

use std::sync::Arc;

use async_std::prelude::*;
use async_std::{
    channel::{Receiver, Sender},
    sync::Mutex,
};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::credential_service::{CredentialServiceClient, UsbState};

#[derive(Debug)]
pub(crate) struct ViewModel<C>
where
    C: CredentialServiceClient + Send,
{
    credential_service: Arc<Mutex<C>>,
    tx_update: Sender<ViewUpdate>,
    rx_event: Receiver<ViewEvent>,
    bg_update: Sender<BackgroundEvent>,
    bg_event: Receiver<BackgroundEvent>,
    title: String,
    operation: Operation,

    // This includes devices like platform authenticator, USB, hybrid
    devices: Vec<Device>,
    selected_device: Option<Device>,

    providers: Vec<Provider>,

    usb_pin_tx: Option<Arc<Mutex<mpsc::Sender<String>>>>,
    usb_cred_tx: Option<Arc<Mutex<mpsc::Sender<String>>>>,

    hybrid_qr_state: HybridState,
    hybrid_qr_code_data: Option<Vec<u8>>,

    hybrid_linked_state: HybridState,
}

impl<C: CredentialServiceClient + Send> ViewModel<C> {
    pub(crate) fn new(
        operation: Operation,
        credential_service: C,
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
            providers: Vec::new(),
            usb_pin_tx: None,
            usb_cred_tx: None,
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
                Transport::Usb => {
                    todo!("Implement cancellation for USB");
                }
                Transport::HybridQr => {
                    todo!("Implement cancellation for Hybrid QR");
                }
                _ => {
                    todo!();
                }
            };
        }

        // start discovery for newly selected device
        match device.transport {
            Transport::Usb => {
                let cred_service = self.credential_service.clone();
                let tx = self.bg_update.clone();
                let mut stream = {
                    let cred_service = cred_service.lock().await;
                    cred_service.get_usb_credential().await
                };
                async_std::task::spawn(async move {
                    // TODO: add cancellation
                    while let Some(usb_state) = stream.next().await {
                        // forward to background event loop
                        tx.send(BackgroundEvent::UsbStateChanged(usb_state))
                            .await
                            .unwrap();
                    }
                });
            }
            Transport::HybridQr => {
                let tx = self.bg_update.clone();
                let cred_service = self.credential_service.clone();
                let mut stream = cred_service.lock().await.get_hybrid_credential().await;
                async_std::task::spawn(async move {
                    while let Some(state) = stream.next().await {
                        // forward to background event loop
                        tx.send(BackgroundEvent::HybridQrStateChanged(state.into()))
                            .await
                            .unwrap();
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
                    if let Some(pin_tx) = self.usb_pin_tx.take() {
                        if pin_tx.lock().await.send(pin).await.is_err() {
                            error!("Failed to send pin to device");
                        }
                    }
                }
                Event::View(ViewEvent::CredentialSelected(cred_id)) => {
                    println!(
                        "Credential selected: {:?}. Current Device: {:?}",
                        cred_id, self.selected_device
                    );

                    if let Some(cred_tx) = self.usb_cred_tx.take() {
                        if cred_tx.lock().await.send(cred_id.clone()).await.is_err() {
                            error!("Failed to send selected credential to device");
                        }
                    }
                }

                Event::Background(BackgroundEvent::UsbPressed) => {
                    println!("UsbPressed");
                }
                Event::Background(BackgroundEvent::UsbStateChanged(state)) => {
                    // TODO: do we need to store the USB state?
                    match state {
                        UsbState::Connected => {
                            info!("Found USB device")
                        }

                        UsbState::NeedsPin {
                            attempts_left,
                            pin_tx,
                        } => {
                            let _ = self.usb_pin_tx.insert(Arc::new(Mutex::new(pin_tx)));
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
                            self.tx_update.send(ViewUpdate::Completed).await.unwrap();
                        }
                        UsbState::SelectingDevice => {
                            self.tx_update
                                .send(ViewUpdate::SelectingDevice)
                                .await
                                .unwrap();
                        }
                        UsbState::Idle | UsbState::Waiting => {}
                        UsbState::SelectCredential { creds, cred_tx } => {
                            let _ = self.usb_cred_tx.insert(Arc::new(Mutex::new(cred_tx)));
                            self.tx_update
                                .send(ViewUpdate::SetCredentials(creds))
                                .await
                                .unwrap();
                        }
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
                        HybridState::Connecting => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update
                                .send(ViewUpdate::HybridConnecting)
                                .await
                                .unwrap();
                        }
                        HybridState::Connected => {
                            self.hybrid_qr_code_data = None;
                            self.tx_update
                                .send(ViewUpdate::HybridConnected)
                                .await
                                .unwrap();
                        }
                        HybridState::Completed => {
                            self.hybrid_qr_code_data = None;
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
    SelectingDevice,

    UsbNeedsPin { attempts_left: Option<u32> },
    UsbNeedsUserVerification { attempts_left: Option<u32> },
    UsbNeedsUserPresence,

    HybridNeedsQrCode(String),
    HybridConnecting,
    HybridConnected,

    Completed,
    Failed,
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
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) username: Option<String>,
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

    /// QR code flow is starting, awaiting QR code scan and BLE advert from phone.
    Started(String),

    /// BLE advert received, connecting to caBLE tunnel with shared secret.
    Connecting,

    /// Connected to device via caBLE tunnel.
    Connected,

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
            crate::credential_service::hybrid::HybridState::Connecting => HybridState::Connecting,
            crate::credential_service::hybrid::HybridState::Connected => HybridState::Connected,
            crate::credential_service::hybrid::HybridState::Completed => HybridState::Completed,
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

#[derive(Debug, Default)]
pub struct UserVerificationMethod;
