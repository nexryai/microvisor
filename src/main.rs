mod helper_client;
mod storage;
mod ui;

use adw::prelude::*;
use gtk::{gio, glib};
use microvisor::diagnostics;

const APP_ID: &str = "me.nexryai.microvisor";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> glib::ExitCode {
    diagnostics::info("application", format_args!("starting Microvisor {VERSION}"));
    gio::resources_register_include!("microvisor.gresource")
        .expect("Could not register application resources");
    diagnostics::debug(
        "application",
        format_args!("registered application resources"),
    );

    let app = adw::Application::builder()
        .application_id(APP_ID)
        .resource_base_path("/me/nexryai/microvisor")
        .build();

    app.connect_startup(setup_actions);
    app.connect_activate(|app| {
        diagnostics::info("application", format_args!("activation requested"));
        ui::window::present(app);
    });
    let exit_code = app.run();
    diagnostics::info(
        "application",
        format_args!("application stopped with {exit_code:?}"),
    );
    exit_code
}

fn setup_actions(app: &adw::Application) {
    diagnostics::debug(
        "application",
        format_args!("installing application actions"),
    );
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_, _| {
            diagnostics::info("application", format_args!("quit action activated"));
            app.quit();
        }
    ));
    app.add_action(&quit);
    app.set_accels_for_action("app.quit", &["<primary>q"]);
    app.set_accels_for_action("win.add-profile", &["<primary>n"]);
    app.set_accels_for_action("app.shortcuts", &["<primary>question"]);

    let shortcuts = gio::SimpleAction::new("shortcuts", None);
    shortcuts.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_, _| {
            diagnostics::info("application", format_args!("shortcuts action activated"));
            if let Some(window) = app.active_window() {
                ui::shortcuts_dialog::present(&window);
            } else {
                diagnostics::warn(
                    "application",
                    format_args!("could not present shortcuts without an active window"),
                );
            }
        }
    ));
    app.add_action(&shortcuts);

    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_, _| {
            diagnostics::info("application", format_args!("about action activated"));
            let dialog = adw::AboutDialog::builder()
                .application_name("Microvisor")
                .application_icon(APP_ID)
                .developer_name("nexryai")
                .version(VERSION)
                .comments("Protect application data directories with generated SELinux policy.")
                .website("https://github.com/nexryai/microvisor")
                .issue_url("https://github.com/nexryai/microvisor/issues")
                .license_type(gtk::License::MitX11)
                .build();
            if let Some(window) = app.active_window() {
                dialog.present(Some(&window));
            } else {
                diagnostics::warn(
                    "application",
                    format_args!("could not present About dialog without an active window"),
                );
            }
        }
    ));
    app.add_action(&about);
}
