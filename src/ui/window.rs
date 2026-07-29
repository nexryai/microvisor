use crate::storage;
use crate::ui::profile_dialog;
use adw::prelude::*;
use gtk::glib;
use microvisor::diagnostics;
use microvisor::model::ProtectionProfile;
use std::{path::Path, process::Command, rc::Rc};

pub fn present(app: &adw::Application) {
    if let Some(window) = app.active_window() {
        diagnostics::debug(
            "ui.window",
            format_args!("presenting the existing main window"),
        );
        window.present();
        return;
    }

    diagnostics::info("ui.window", format_args!("creating the main window"));
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::IconTheme::for_display(&display).add_resource_path("/me/nexryai/microvisor/icons");
    } else {
        diagnostics::warn(
            "ui.window",
            format_args!("no default display was available while loading icons"),
        );
    }

    let MainWindowWidgets {
        window,
        toast_overlay,
        content_stack,
        profiles_list,
        selinux_banner,
    } = build_main_window(app);
    let state = Rc::new(WindowState {
        window: window.downgrade(),
        toast_overlay,
        content_stack,
        profiles_list,
        selinux_banner,
    });

    let add_action = gio::SimpleAction::new("add-profile", None);
    // The window owns this action, so the action must keep the shared state alive. WindowState
    // holds only a weak reference back to the window to avoid creating a reference cycle.
    let action_state = state.clone();
    add_action.connect_activate(move |_, _| {
        diagnostics::info(
            "ui.window",
            format_args!("Add Application action activated"),
        );
        let Some(window) = action_state.window.upgrade() else {
            diagnostics::warn(
                "ui.window",
                format_args!("ignored Add Application because the window was closed"),
            );
            return;
        };
        let weak_refresh_state = Rc::downgrade(&action_state);
        profile_dialog::present(
            &window,
            &action_state.toast_overlay,
            ProtectionProfile::new(),
            move || {
                if let Some(state) = weak_refresh_state.upgrade() {
                    state.refresh();
                } else {
                    diagnostics::warn(
                        "ui.window",
                        format_args!("could not refresh a closed main window"),
                    );
                }
            },
        );
    });
    window.add_action(&add_action);

    let status_action = gio::SimpleAction::new("system-status", None);
    status_action.connect_activate(glib::clone!(
        #[weak]
        window,
        move |_, _| {
            diagnostics::info("ui.window", format_args!("System Status action activated"));
            present_system_status(&window);
        }
    ));
    window.add_action(&status_action);

    state.refresh();
    state.update_banner();
    window.present();
    diagnostics::info("ui.window", format_args!("main window presented"));
}

struct MainWindowWidgets {
    window: adw::ApplicationWindow,
    toast_overlay: adw::ToastOverlay,
    content_stack: gtk::Stack,
    profiles_list: gtk::ListBox,
    selinux_banner: adw::Banner,
}

fn build_main_window(app: &adw::Application) -> MainWindowWidgets {
    let primary_menu = gio::Menu::new();
    let status_section = gio::Menu::new();
    status_section.append(Some("System Status"), Some("win.system-status"));
    primary_menu.append_section(None, &status_section);

    let application_section = gio::Menu::new();
    application_section.append(Some("Keyboard Shortcuts"), Some("app.shortcuts"));
    application_section.append(Some("About Microvisor"), Some("app.about"));
    primary_menu.append_section(None, &application_section);

    let title = adw::WindowTitle::builder()
        .title("Microvisor")
        .subtitle("SELinux Application Protection")
        .build();
    let header = adw::HeaderBar::builder().title_widget(&title).build();
    let add_button = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .action_name("win.add-profile")
        .tooltip_text("Add Application")
        .build();
    let menu_button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&primary_menu)
        .tooltip_text("Main Menu")
        .build();
    header.pack_end(&add_button);
    header.pack_end(&menu_button);

    let empty_add_button = gtk::Button::builder()
        .label("Add Application")
        .action_name("win.add-profile")
        .halign(gtk::Align::Center)
        .css_classes(["suggested-action", "pill"])
        .build();
    let empty_page = adw::StatusPage::builder()
        .icon_name("me.nexryai.microvisor-symbolic")
        .title("No Protected Applications")
        .description(
            "Add an application and select the data directories that only its SELinux domain \
             should access.",
        )
        .child(&empty_add_button)
        .build();

    let profiles_heading = gtk::Label::builder()
        .label("Protected Applications")
        .xalign(0.0)
        .css_classes(["title-2"])
        .build();
    let profiles_description = gtk::Label::builder()
        .label(
            "Each application runs in a dedicated SELinux domain. Other domains are denied \
             access to its protected data type.",
        )
        .xalign(0.0)
        .wrap(true)
        .css_classes(["dim-label"])
        .build();
    let profiles_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let profiles_page = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    profiles_page.append(&profiles_heading);
    profiles_page.append(&profiles_description);
    profiles_page.append(&profiles_list);

    let content_stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    content_stack.add_named(&empty_page, Some("empty"));
    content_stack.add_named(&profiles_page, Some("profiles"));

    let selinux_banner = adw::Banner::builder().revealed(false).build();
    let content_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(18)
        .margin_end(18)
        .build();
    content_box.append(&selinux_banner);
    content_box.append(&content_stack);

    let clamp = adw::Clamp::builder()
        .maximum_size(720)
        .tightening_threshold(560)
        .child(&content_box)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&scrolled));

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&toolbar));
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Microvisor")
        .default_width(760)
        .default_height(620)
        .width_request(360)
        .height_request(420)
        .content(&toast_overlay)
        .build();

    MainWindowWidgets {
        window,
        toast_overlay,
        content_stack,
        profiles_list,
        selinux_banner,
    }
}

struct WindowState {
    window: glib::WeakRef<adw::ApplicationWindow>,
    toast_overlay: adw::ToastOverlay,
    content_stack: gtk::Stack,
    profiles_list: gtk::ListBox,
    selinux_banner: adw::Banner,
}

impl WindowState {
    fn refresh(self: &Rc<Self>) {
        diagnostics::debug("ui.window", format_args!("refreshing the profile list"));
        while let Some(child) = self.profiles_list.first_child() {
            self.profiles_list.remove(&child);
        }

        let profiles = match storage::load_profiles() {
            Ok(profiles) => profiles,
            Err(error) => {
                diagnostics::error(
                    "ui.window",
                    format_args!("could not load profiles: {error:#}"),
                );
                let message = format!("Could not load profiles: {error}");
                self.toast_overlay.add_toast(adw::Toast::new(&message));
                Vec::new()
            }
        };
        diagnostics::info(
            "ui.window",
            format_args!("loaded {} local profile(s)", profiles.len()),
        );

        self.content_stack
            .set_visible_child_name(if profiles.is_empty() {
                "empty"
            } else {
                "profiles"
            });

        for profile in profiles {
            let subtitle = format!(
                "{} · {} protected {}",
                profile.executable.display(),
                profile.data_directories.len(),
                if profile.data_directories.len() == 1 {
                    "directory"
                } else {
                    "directories"
                }
            );
            let row = adw::ActionRow::builder()
                .title(&profile.name)
                .subtitle(&subtitle)
                .activatable(true)
                .build();
            let application_icon = gtk::Image::from_icon_name("application-x-executable-symbolic");
            row.add_prefix(&application_icon);

            let status = gtk::Label::builder()
                .label(if profile.applied {
                    "Protected"
                } else {
                    "Not Applied"
                })
                .css_classes(["dim-label"])
                .valign(gtk::Align::Center)
                .build();
            let next_icon = gtk::Image::from_icon_name("go-next-symbolic");
            row.add_suffix(&status);
            row.add_suffix(&next_icon);

            let weak_state = Rc::downgrade(self);
            row.connect_activated(move |_| {
                let Some(state) = weak_state.upgrade() else {
                    diagnostics::warn(
                        "ui.window",
                        format_args!("ignored profile activation because the window was closed"),
                    );
                    return;
                };
                let Some(window) = state.window.upgrade() else {
                    diagnostics::warn(
                        "ui.window",
                        format_args!("ignored profile activation because the window was closed"),
                    );
                    return;
                };
                diagnostics::info("ui.window", format_args!("opening profile {}", profile.id));
                let weak_refresh_state = Rc::downgrade(&state);
                profile_dialog::present(
                    &window,
                    &state.toast_overlay,
                    profile.clone(),
                    move || {
                        if let Some(state) = weak_refresh_state.upgrade() {
                            state.refresh();
                        } else {
                            diagnostics::warn(
                                "ui.window",
                                format_args!("could not refresh a closed main window"),
                            );
                        }
                    },
                );
            });
            self.profiles_list.append(&row);
        }
    }

    fn update_banner(&self) {
        diagnostics::debug(
            "ui.window",
            format_args!("checking SELinux enforcement state"),
        );
        let status = Command::new("getenforce").output();
        match status {
            Ok(output) => {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                diagnostics::info(
                    "ui.window",
                    format_args!(
                        "getenforce exited with {} and reported {value:?}",
                        output.status
                    ),
                );
                if value == "Disabled" {
                    self.selinux_banner
                        .set_title("SELinux is disabled. Protection cannot be applied.");
                    self.selinux_banner.set_revealed(true);
                } else if value == "Permissive" {
                    self.selinux_banner
                        .set_title("SELinux is permissive. Rules will be logged but not enforced.");
                    self.selinux_banner.set_revealed(true);
                } else {
                    self.selinux_banner.set_revealed(false);
                }
            }
            Err(error) => {
                diagnostics::warn(
                    "ui.window",
                    format_args!("could not execute getenforce: {error}"),
                );
                self.selinux_banner
                    .set_title("SELinux tools were not found on this system.");
                self.selinux_banner.set_revealed(true);
            }
        }
    }
}

fn present_system_status(parent: &adw::ApplicationWindow) {
    diagnostics::debug(
        "ui.window",
        format_args!("collecting system status information"),
    );
    let enforcement = command_output("getenforce", &[]).unwrap_or_else(|| "Unavailable".into());
    let semodule =
        command_output("semodule", &["--version"]).unwrap_or_else(|| "Unavailable".into());
    let helper = if Path::new("/usr/libexec/microvisor-helper").is_file() {
        "Installed"
    } else {
        "Not installed"
    };
    let policy_devel = if Path::new("/usr/share/selinux/devel/Makefile").is_file() {
        "Installed"
    } else {
        "Not installed"
    };

    let body = format!(
        "Enforcement: {enforcement}\n\
         SELinux userspace: {semodule}\n\
         Privileged helper: {helper}\n\
         Policy development files: {policy_devel}\n\n\
         Microvisor requires SELinux userspace 3.6 or newer for CIL deny rules."
    );
    let dialog = adw::AlertDialog::builder()
        .heading("System Status")
        .body(&body)
        .build();
    dialog.add_response("close", "Close");
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");
    dialog.present(Some(parent));
}

fn command_output(command: &str, arguments: &[&str]) -> Option<String> {
    let output = match Command::new(command).args(arguments).output() {
        Ok(output) => output,
        Err(error) => {
            diagnostics::warn(
                "ui.window",
                format_args!("could not execute {command}: {error}"),
            );
            return None;
        }
    };
    if !output.status.success() {
        diagnostics::warn(
            "ui.window",
            format_args!("{command} exited with {}", output.status),
        );
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Some(if stdout.is_empty() { stderr } else { stdout })
}
