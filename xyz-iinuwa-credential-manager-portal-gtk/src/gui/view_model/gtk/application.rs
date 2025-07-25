use async_std::channel::{Receiver, Sender};
use gettextrs::gettext;
use tracing::{debug, info};

use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{gdk, gio, glib};

use super::{window::ExampleApplicationWindow, ViewModel};
use crate::config::{APP_ID, PKGDATADIR, PROFILE, VERSION};
use crate::gui::view_model::{ViewEvent, ViewUpdate};

mod imp {
    use super::*;
    use glib::{clone, WeakRef};
    use std::{
        cell::{OnceCell, RefCell},
        time::Duration,
    };

    #[derive(Debug, Default)]
    pub struct ExampleApplication {
        pub window: OnceCell<WeakRef<ExampleApplicationWindow>>,

        pub(super) tx: RefCell<Option<Sender<ViewEvent>>>,
        pub(super) rx: RefCell<Option<Receiver<ViewUpdate>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ExampleApplication {
        const NAME: &'static str = "ExampleApplication";
        type Type = super::ExampleApplication;
        type ParentType = gtk::Application;
    }

    impl ObjectImpl for ExampleApplication {}

    impl ApplicationImpl for ExampleApplication {
        fn activate(&self) {
            debug!("GtkApplication<ExampleApplication>::activate");
            self.parent_activate();
            let app = self.obj();

            if let Some(window) = self.window.get() {
                let window = window.upgrade().unwrap();
                window.present();
                return;
            }

            let tx = self.tx.take().expect("sender to be initiated");
            let rx = self.rx.take().expect("receiver to be initiated");
            let view_model = ViewModel::new(tx, rx);
            let vm2 = view_model.clone();
            let window = ExampleApplicationWindow::new(&app, view_model);
            let window2 = window.clone();
            vm2.clone().connect_completed_notify(move |vm| {
                if vm.completed() {
                    glib::spawn_future_local(clone!(
                        #[weak]
                        window2,
                        async move {
                            // Wait to show confirmation before closing.
                            async_std::task::sleep(Duration::from_millis(500)).await;
                            gtk::prelude::WidgetExt::activate_action(&window2, "window.close", None)
                                .unwrap()
                        }
                    ));
                }
            });
            self.window
                .set(window.downgrade())
                .expect("Window already set.");

            app.main_window().present();
        }

        fn startup(&self) {
            debug!("GtkApplication<ExampleApplication>::startup");
            self.parent_startup();
            let app = self.obj();

            // Set icons for shell
            gtk::Window::set_default_icon_name(APP_ID);

            app.setup_css();
            app.setup_gactions();
            app.setup_accels();
        }
    }

    impl GtkApplicationImpl for ExampleApplication {}
}

glib::wrapper! {
    pub struct ExampleApplication(ObjectSubclass<imp::ExampleApplication>)
        @extends gio::Application, gtk::Application,
        @implements gio::ActionMap, gio::ActionGroup;
}

impl ExampleApplication {
    fn main_window(&self) -> ExampleApplicationWindow {
        self.imp().window.get().unwrap().upgrade().unwrap()
    }

    fn setup_gactions(&self) {
        // Quit
        let action_quit = gio::ActionEntry::builder("quit")
            .activate(move |app: &Self, _, _| {
                // This is needed to trigger the delete event and saving the window state
                app.main_window().close();
                app.quit();
            })
            .build();

        // About
        let action_about = gio::ActionEntry::builder("about")
            .activate(|app: &Self, _, _| {
                app.show_about_dialog();
            })
            .build();
        self.add_action_entries([action_quit, action_about]);
    }

    // Sets up keyboard shortcuts
    fn setup_accels(&self) {
        self.set_accels_for_action("app.quit", &["<Control>q"]);
        self.set_accels_for_action("window.close", &["<Control>w"]);
    }

    fn setup_css(&self) {
        let provider = gtk::CssProvider::new();
        provider.load_from_resource("/xyz/iinuwa/CredentialManager/style.css");
        if let Some(display) = gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    }

    fn show_about_dialog(&self) {
        let dialog = gtk::AboutDialog::builder()
            .logo_icon_name(APP_ID)
            // Insert your license of choice here
            // .license_type(gtk::License::MitX11)
            .website("https://github.com/iinuwa/linux-webauthn-portal-api")
            .version(VERSION)
            .transient_for(&self.main_window())
            .translator_credits(gettext("translator-credits"))
            .modal(true)
            .authors(vec!["Isaiah Inuwa"])
            .artists(vec!["Isaiah Inuwa"])
            .build();

        dialog.present();
    }

    pub fn run(&self) -> glib::ExitCode {
        info!("Credential Manager ({})", APP_ID);
        info!("Version: {} ({})", VERSION, PROFILE);
        info!("Datadir: {}", PKGDATADIR);

        ApplicationExtManual::run(self)
    }

    pub(crate) fn new(tx: Sender<ViewEvent>, rx: Receiver<ViewUpdate>) -> Self {
        let app: Self = glib::Object::builder()
            .property("application-id", APP_ID)
            .property("resource-base-path", "/xyz/iinuwa/CredentialManager/")
            .build();
        app.imp().tx.replace(Some(tx));
        app.imp().rx.replace(Some(rx));
        app
    }
}
