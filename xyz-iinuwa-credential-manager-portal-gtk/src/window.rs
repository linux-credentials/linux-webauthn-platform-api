use std::cell::RefCell;

use glib::Properties;
use gtk::gdk::Texture;
use gtk::subclass::prelude::*;
use gtk::{
    gio,
    glib::{self, clone},
};
use gtk::{prelude::*, Picture};

use crate::application::ExampleApplication;
use crate::config::{APP_ID, PROFILE};
use crate::view_model::gtk::{device::DeviceObject, ViewModel};
use crate::view_model::Transport;

mod imp {
    use gtk::Picture;

    use super::*;

    #[derive(Debug, Properties, gtk::CompositeTemplate)]
    #[properties(wrapper_type = super::ExampleApplicationWindow)]
    #[template(resource = "/xyz/iinuwa/CredentialManager/ui/window.ui")]
    pub struct ExampleApplicationWindow {
        #[template_child]
        pub headerbar: TemplateChild<gtk::HeaderBar>,
        pub settings: gio::Settings,
        #[property(get, set)]
        pub view_model: RefCell<Option<ViewModel>>,

        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,

        #[template_child]
        pub usb_pin_entry: TemplateChild<gtk::PasswordEntry>,

        #[template_child]
        pub qr_code_pic: TemplateChild<Picture>,
    }

    #[gtk::template_callbacks]
    impl ExampleApplicationWindow {
        #[template_callback]
        fn handle_button_clicked(&self, _: &gtk::Button) {
            println!("clicked");
            let view_model = &self.view_model.borrow();
            let view_model = view_model.as_ref().unwrap();
            glib::spawn_future_local(clone!(
                #[weak]
                view_model,
                async move {
                    view_model.send_thingy().await;
                }
            ));
        }

        #[template_callback]
        fn handle_usb_pin_entered(&self, entry: &gtk::PasswordEntry) {
            let view_model = &self.view_model.borrow();
            let view_model = view_model.as_ref().unwrap();
            let pin = entry.text().to_string();
            glib::spawn_future_local(clone!(
                #[weak]
                view_model,
                async move {
                    view_model.send_usb_device_pin(pin).await;
                }
            ));
        }
    }

    impl Default for ExampleApplicationWindow {
        fn default() -> Self {
            Self {
                headerbar: TemplateChild::default(),
                settings: gio::Settings::new(APP_ID),
                view_model: RefCell::default(),
                stack: TemplateChild::default(),
                usb_pin_entry: TemplateChild::default(),
                qr_code_pic: TemplateChild::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ExampleApplicationWindow {
        const NAME: &'static str = "ExampleApplicationWindow";
        type Type = super::ExampleApplicationWindow;
        type ParentType = gtk::ApplicationWindow;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.bind_template_callbacks();
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    #[glib::derived_properties]
    impl ObjectImpl for ExampleApplicationWindow {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();

            // Devel Profile
            if PROFILE == "Devel" {
                obj.add_css_class("devel");
            }

            // Load latest window state
            obj.load_window_size();
        }
    }

    impl WidgetImpl for ExampleApplicationWindow {}
    impl WindowImpl for ExampleApplicationWindow {
        // Save window state on delete event
        fn close_request(&self) -> glib::Propagation {
            if let Err(err) = self.obj().save_window_size() {
                tracing::warn!("Failed to save window state, {}", &err);
            }

            // Pass close request on to the parent
            self.parent_close_request()
        }
    }

    impl ApplicationWindowImpl for ExampleApplicationWindow {}
}

glib::wrapper! {
    pub struct ExampleApplicationWindow(ObjectSubclass<imp::ExampleApplicationWindow>)
        @extends gtk::Widget, gtk::Window, gtk::ApplicationWindow,
        @implements gio::ActionMap, gio::ActionGroup, gtk::Root;

}

impl ExampleApplicationWindow {
    pub fn new(app: &ExampleApplication, view_model: ViewModel) -> Self {
        let window: ExampleApplicationWindow = glib::Object::builder()
            .property("application", app)
            .property("view-model", view_model)
            .build();
        window.setup_callbacks();
        window
    }

    fn setup_callbacks(&self) {
        let view_model = &self.view_model();
        let view_model = view_model.as_ref().expect("view model to exist");
        let stack: &gtk::Stack = &self.imp().stack.get();
        let qr_code_pic: &Picture = &self.imp().qr_code_pic.get();
        view_model.connect_selected_device_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                let d = vm.selected_device();
                let d = d
                    .and_downcast_ref::<DeviceObject>()
                    .expect("selected device to exist at notify");
                match d.transport().try_into() {
                    Ok(Transport::Usb) => stack.set_visible_child_name("usb"),
                    Ok(Transport::HybridQr) => stack.set_visible_child_name("hybrid_qr"),
                    _ => {}
                };
            }
        ));

        view_model.connect_qr_code_paintable_notify(clone!(
            #[weak]
            qr_code_pic,
            move |vm| {
                let paintable = vm.qr_code_paintable();
                let paintable = paintable.and_downcast_ref::<Texture>();
                qr_code_pic.set_paintable(paintable);
            }
        ));

        view_model.connect_completed_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                if vm.completed() {
                    stack.set_visible_child_name("completed");
                }
            }
        ));

        view_model.connect_failed_notify(clone!(
            #[weak]
            stack,
            move |vm| {
                if vm.completed() {
                    stack.set_visible_child_name("failed");
                }
            }
        ));

        view_model.connect_credentials_notify(clone!(
            #[weak]
            stack,
            move |_vm| {
                stack.set_visible_child_name("choose_credential");
            }
        ));
    }

    fn save_window_size(&self) -> Result<(), glib::BoolError> {
        let imp = self.imp();

        let (width, height) = self.default_size();

        imp.settings.set_int("window-width", width)?;
        imp.settings.set_int("window-height", height)?;

        imp.settings
            .set_boolean("is-maximized", self.is_maximized())?;

        Ok(())
    }

    fn load_window_size(&self) {
        let imp = self.imp();

        let width = imp.settings.int("window-width");
        let height = imp.settings.int("window-height");
        let is_maximized = imp.settings.boolean("is-maximized");

        self.set_default_size(width, height);

        if is_maximized {
            self.maximize();
        }
    }
}
