pub mod credential;
pub mod device;

use async_std::channel::{Receiver, Sender};
use glib::clone;
use gtk::gdk::Texture;
use gtk::gdk_pixbuf::Pixbuf;
use gtk::gio::{self, Cancellable, MemoryInputStream};
use gtk::glib::{self, Bytes};
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use qrcode::QrCode;
use tracing::debug;

use self::credential::CredentialObject;
use self::device::DeviceObject;

use super::Transport;
use super::{Credential, Device};
use super::{ViewEvent, ViewUpdate};

mod imp {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::ViewModel)]
    pub struct ViewModel {
        #[property(get, set)]
        pub title: RefCell<String>,

        #[property(get, set)]
        pub devices: RefCell<gtk::ListBox>,

        #[property(get, set)]
        pub credentials: RefCell<gtk::ListBox>,

        #[property(get, set)]
        pub selected_device: RefCell<Option<DeviceObject>>,

        #[property(get, set)]
        pub usb_pin_entry_visible: RefCell<bool>,

        #[property(get, set)]
        pub prompt: RefCell<String>,

        #[property(get, set)]
        pub completed: RefCell<bool>,

        #[property(get, set)]
        pub failed: RefCell<bool>,

        // pub(super) vm: RefCell<Option<crate::view_model::ViewModel>>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
        // hybrid_qr_state: HybridState,
        // hybrid_qr_code_data: Option<Vec<u8>>,
        #[property(get, set)]
        pub qr_code_paintable: RefCell<Option<Texture>>,

        #[property(get, set)]
        pub qr_code_visible: RefCell<bool>,

        #[property(get, set)]
        pub qr_spinner_visible: RefCell<bool>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for ViewModel {
        const NAME: &'static str = "CredentialManagerViewModel";
        type Type = super::ViewModel;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for ViewModel {}
}

glib::wrapper! {
    pub struct ViewModel(ObjectSubclass<imp::ViewModel>);
}

impl ViewModel {
    pub(crate) fn new(tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let view_model: Self = glib::Object::builder().build();
        view_model.setup_channel(tx, rx);

        {
            let tx = view_model.imp().tx.borrow();
            let tx = tx.as_ref().expect("tx to exist");
            tx.send_blocking(ViewEvent::Initiated).unwrap();
        }

        view_model
    }

    fn setup_channel(&self, tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) {
        self.imp().tx.replace(Some(tx));
        self.imp().rx.replace(Some(rx));
        glib::spawn_future_local(clone!(
            #[weak(rename_to = view_model)]
            self,
            async move {
                loop {
                    let rx = {
                        let rx_ptr = view_model.imp().rx.borrow();
                        rx_ptr.as_ref().expect("rx to exist").clone()
                    };
                    match rx.recv().await {
                        Ok(update) => {
                            // TODO: hack so I don't have to unset this in every event manually.
                            view_model.set_usb_pin_entry_visible(false);
                            match update {
                                ViewUpdate::SetTitle(title) => view_model.set_title(title),
                                ViewUpdate::SetDevices(devices) => {
                                    view_model.update_devices(&devices)
                                }
                                ViewUpdate::SetCredentials(credentials) => {
                                    view_model.update_credentials(&credentials)
                                }
                                ViewUpdate::SelectingDevice => view_model.selecting_device(),
                                ViewUpdate::WaitingForDevice(device) => {
                                    view_model.waiting_for_device(&device)
                                }
                                ViewUpdate::UsbNeedsPin { attempts_left } => {
                                    let prompt = match attempts_left {
                                        Some(1) => {
                                            "Enter your PIN. 1 attempt remaining.".to_string()
                                        }
                                        Some(attempts_left) => format!(
                                            "Enter your PIN. {attempts_left} attempts remaining."
                                        ),
                                        None => "Enter your PIN.".to_string(),
                                    };
                                    view_model.set_prompt(prompt);
                                    view_model.set_usb_pin_entry_visible(true);
                                }
                                ViewUpdate::UsbNeedsUserVerification { attempts_left } => {
                                    let prompt = match attempts_left {
                                        Some(1) => "Touch your device again. 1 attempt remaining.".to_string(),
                                        Some(attempts_left) => format!("Touch your device again. {attempts_left} attempts remaining."),
                                        None => "Touch your device.".to_string(),
                                    };
                                    view_model.set_prompt(prompt);
                                }
                                ViewUpdate::UsbNeedsUserPresence => {
                                    view_model.set_prompt("Touch your device");
                                }
                                ViewUpdate::HybridNeedsQrCode(qr_code) => {
                                    view_model.set_prompt("Scan the QR code with your device to begin authentication.");
                                    let texture = view_model.draw_qr_code(&qr_code);
                                    view_model.set_qr_code_paintable(&texture);
                                    view_model.set_qr_code_visible(true);
                                    view_model.set_qr_spinner_visible(true);
                                }
                                ViewUpdate::HybridConnecting => {
                                    view_model.set_qr_code_visible(false);
                                    _ = view_model.qr_code_paintable().take();
                                    view_model.set_prompt(
                                        "Connecting to your device. Make sure both devices are near each other and have Bluetooth enabled.",
                                    );
                                    view_model.set_qr_spinner_visible(true);
                                }
                                ViewUpdate::HybridConnected => {
                                    view_model.set_qr_code_visible(false);
                                    _ = view_model.qr_code_paintable().take();
                                    view_model.set_prompt(
                                        "Device connected. Follow the instructions on your device",
                                    );
                                    view_model.set_qr_spinner_visible(false);
                                }
                                ViewUpdate::Completed => {
                                    view_model.set_qr_spinner_visible(false);
                                    view_model.set_completed(true);
                                }
                                ViewUpdate::Failed => {
                                    view_model.set_qr_spinner_visible(false);
                                    view_model.set_failed(true);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("ViewModel event listener interrupted: {}", e);
                            break;
                        }
                    }
                }
            }
        ));
    }

    fn update_devices(&self, devices: &[Device]) {
        let vec: Vec<DeviceObject> = devices
            .iter()
            .map(|d| {
                let device_object: DeviceObject = d.into();
                device_object
            })
            .collect();
        let model = gio::ListStore::new::<DeviceObject>();
        model.extend_from_slice(&vec);
        let tx = self.get_sender();
        let device_list = gtk::ListBox::new();
        device_list.bind_model(Some(&model), move |item| -> gtk::Widget {
            let device = item.downcast_ref::<DeviceObject>().unwrap();
            let transport: Transport = device.transport().try_into().unwrap();
            let icon_name = match transport {
                Transport::Ble => "bluetooth-symbolic",
                Transport::Internal => "computer-symbolic",
                Transport::HybridQr => "phone-symbolic",
                Transport::HybridLinked => "phone-symbolic",
                Transport::Nfc => "nfc-symbolic",
                Transport::Usb => "media-removable-symbolic",
                // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
                // _ => "question-symbolic",
            };

            let b = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .build();
            let icon = gtk::Image::builder().icon_name(icon_name).build();
            let label = gtk::Label::builder().label(device.name()).build();
            b.append(&icon);
            b.append(&label);

            let button = gtk::Button::builder().name(device.id()).child(&b).build();
            let tx = tx.clone();
            button.connect_clicked(move |button| {
                let id = button.widget_name().to_string();
                let tx = tx.clone();
                glib::spawn_future_local(async move {
                    tx.send(ViewEvent::DeviceSelected(id)).await.unwrap();
                });
            });
            button.into()
        });
        self.set_devices(device_list);
    }

    fn update_credentials(&self, credentials: &[Credential]) {
        let vec: Vec<CredentialObject> = credentials
            .iter()
            .map(|d| {
                let credential_object: CredentialObject = d.into();
                credential_object
            })
            .collect();
        let model = gio::ListStore::new::<CredentialObject>();
        model.extend_from_slice(&vec);
        let tx = self.get_sender();
        let credential_list = gtk::ListBox::new();
        credential_list.bind_model(Some(&model), move |item| -> gtk::Widget {
            let credential = item.downcast_ref::<CredentialObject>().unwrap();
            // TODO: need a "credential type" to determine the icon, e.g. passkey vs. password?
            let icon_name = "key-symbolic";
            let b = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .build();
            let icon = gtk::Image::builder().icon_name(icon_name).build();
            let mut display_label = credential.name().to_string();
            if let Some(username) = credential.username() {
                display_label += &format!(" ({username})");
            }
            let label = gtk::Label::builder().label(display_label).build();
            b.append(&icon);
            b.append(&label);

            let button = gtk::Button::builder()
                .name(credential.id())
                .child(&b)
                .build();
            let tx = tx.clone();
            button.connect_clicked(move |button| {
                let id = button.widget_name().to_string();
                let tx = tx.clone();
                glib::spawn_future_local(async move {
                    tx.send(ViewEvent::CredentialSelected(id)).await.unwrap();
                });
            });
            button.into()
        });
        self.set_credentials(credential_list);
    }

    fn waiting_for_device(&self, device: &Device) {
        match device.transport {
            Transport::Usb => {
                self.set_prompt("Insert your security key.");
            }
            Transport::HybridQr => {
                self.set_prompt("");
            }
            Transport::Internal => {}
            _ => {
                todo!();
            }
        }
        let device_object: DeviceObject = device.into();
        self.set_selected_device(device_object);
    }

    fn selecting_device(&self) {
        self.set_prompt("Multiple devices found. Please select with which to proceed.");
    }

    pub async fn send_thingy(&self) {
        self.send_event(ViewEvent::ButtonClicked).await;
    }

    pub async fn send_usb_device_pin(&self, pin: String) {
        self.send_event(ViewEvent::UsbPinEntered(pin)).await;
    }

    fn draw_qr_code(&self, qr_data: &str) -> Texture {
        let qr_code = QrCode::new(qr_data).expect("QR code to be valid");
        let svg_xml = qr_code.render::<qrcode::render::svg::Color>().build();
        let stream = MemoryInputStream::from_bytes(&Bytes::from(svg_xml.as_bytes()));
        let pixbuf = Pixbuf::from_stream_at_scale(&stream, 450, 450, true, None::<&Cancellable>)
            .expect("SVG to render");
        Texture::for_pixbuf(&pixbuf)
    }

    fn get_sender(&self) -> Sender<ViewEvent> {
        let tx: Sender<ViewEvent>;
        {
            let tx_tmp = self.imp().tx.borrow();
            tx = tx_tmp.as_ref().expect("channel to exist").clone();
        }
        tx
    }

    async fn send_event(&self, event: ViewEvent) {
        let tx = self.get_sender();
        tx.send(event).await.unwrap();
    }
}
