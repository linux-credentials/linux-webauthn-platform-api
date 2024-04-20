mod device;

use async_std::channel::{Receiver, Sender};
use gtk::gio;
use gtk::glib;
use glib::clone;
use gtk::prelude::*;
use gtk::subclass::prelude::*;
use tracing::debug;

use self::device::DeviceObject;

use super::Device;
use super::Operation;
use super::Transport;
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

        // pub(super) vm: RefCell<Option<crate::view_model::ViewModel>>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
        // hybrid_qr_state: HybridState,
        // hybrid_qr_code_data: Option<Vec<u8>>,
    }

    // The central trait for subclassing a GObject
    #[glib::object_subclass]
    impl ObjectSubclass for ViewModel {
        const NAME: &'static str = "CredentialManagerViewModel";
        type Type =super::ViewModel;
    }

    // Trait shared by all GObjects
    #[glib::derived_properties]
    impl ObjectImpl for ViewModel { }
}

glib::wrapper! {
    pub struct ViewModel(ObjectSubclass<imp::ViewModel>);
}

impl ViewModel {
    pub(crate) fn new(tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let view_model: Self = glib::Object::builder().build();
        view_model.setup_channel(tx.clone(), rx);

        tx.send_blocking(ViewEvent::Initiated).unwrap();

        view_model
    }

    fn setup_channel(&self, tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) {
        self.imp().tx.replace(Some(tx.clone()));
        self.imp().rx.replace(Some(rx.clone()));
        glib::spawn_future_local(clone!(@weak self as view_model => async move {
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        match update {
                            ViewUpdate::SetTitle(title) => { view_model.set_title(title) },
                            ViewUpdate::SetDevices(devices) => { view_model.update_devices(&devices) }
                        }
                    },
                    Err(e) => {
                        debug!("ViewModel event listener interrupted: {}", e);
                        break;
                    }
                }
            }
        }));
    }

    fn update_devices(&self, devices: &[Device]) {
        let vec: Vec<DeviceObject> = devices.iter().map(|d| {
            let name = match d.transport {
                Transport::Ble => "A Bluetooth device",
                Transport::Internal => "This device",
                Transport::HybridQr => "A mobile device",
                Transport::HybridLinked => "TODO: Linked Device",
                Transport::Nfc => "An NFC device",
                Transport::Usb => "A security key",
                // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
            };
            DeviceObject::new(&d.id, &d.transport, name)
        }).collect();
        let model = gio::ListStore::new::<DeviceObject>();
        model.extend_from_slice(&vec);
        let tx = self.get_sender();
        let device_list = gtk::ListBox::new();
        device_list.bind_model(Some(&model), move |item| -> gtk::Widget {
            let device = item.downcast_ref::<DeviceObject>().unwrap();
            let icon_name = match device.transport().as_ref() {
                "BLE" => "bluetooth-symbolic",
                "Internal" => "computer-symbolic",
                "HybridQr" => "phone-symbolic",
                "HybridLinked" => "phone-symbolic",
                "NFC" => "nfc-symbolic",
                "USB" => "media-removable-symbolic",
                // Transport::PasskeyProvider => ("symbolic-link-symbolic", "ACME Password Manager"),
                _ => "question-symbolic",
            };

            let b = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .build();
            let icon = gtk::Image::builder().icon_name(icon_name).build();
            let label = gtk::Label::builder().label(device.name()).build();
            b.append(&icon);
            b.append(&label);

            let button = gtk::Button::builder()
                .name(device.id())
                .child(&b)
                .build();
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

    pub async fn send_thingy(&self) {
        self.send_event(ViewEvent::ButtonClicked).await;
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
