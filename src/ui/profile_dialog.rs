use crate::helper_client;
use crate::storage;
use crate::ui::text_dialog;
use adw::prelude::*;
use anyhow::Result;
use microvisor::diagnostics;
use microvisor::model::{HelperRequest, ProtectionProfile};
use microvisor::policy;
use std::{cell::RefCell, path::PathBuf, rc::Rc, thread};

pub fn present(
    parent: &adw::ApplicationWindow,
    toast_overlay: &adw::ToastOverlay,
    profile: ProtectionProfile,
    on_saved: impl Fn() + 'static,
) {
    let parent = parent.clone();
    let toast_overlay = toast_overlay.clone();
    let on_saved: Rc<dyn Fn()> = Rc::new(on_saved);
    let original_profile = profile.clone();

    let ProfileDialogWidgets {
        dialog,
        apply_button,
        cancel_button,
        name_row,
        executable_row,
        choose_executable_button,
        directories_list,
        add_directory_row,
        launch_domain_row,
        launch_role_row,
        block_ptrace_row,
        block_fd_use_row,
        preview_policy_row,
        remove_group,
        remove_protection_row,
    } = build_profile_dialog();

    let is_new = profile.name.is_empty() && profile.executable.as_os_str().is_empty();
    diagnostics::info(
        "ui.profile-dialog",
        format_args!(
            "presenting {} profile {} (applied={})",
            if is_new { "new" } else { "existing" },
            profile.id,
            profile.applied
        ),
    );
    dialog.set_title(if is_new {
        "Add Protection"
    } else {
        "Edit Protection"
    });
    apply_button.set_label(if profile.applied { "Update" } else { "Apply" });
    remove_group.set_visible(!is_new);

    name_row.set_text(&profile.name);
    executable_row.set_subtitle(
        profile
            .executable
            .to_str()
            .filter(|value| !value.is_empty())
            .unwrap_or("Select an executable"),
    );
    launch_domain_row.set_text(&profile.launch_domain);
    launch_role_row.set_text(&profile.launch_role);
    block_ptrace_row.set_active(profile.block_ptrace);
    block_fd_use_row.set_active(profile.block_fd_use);
    remove_protection_row.set_title(if profile.applied {
        "Remove Protection"
    } else {
        "Delete Profile"
    });

    let executable = Rc::new(RefCell::new(profile.executable.clone()));
    let directories = Rc::new(RefCell::new(profile.data_directories.clone()));
    refresh_directories(&directories_list, &directories);

    cancel_button.connect_clicked(glib::clone!(
        #[weak]
        dialog,
        move |_| {
            diagnostics::debug("ui.profile-dialog", format_args!("cancel button clicked"));
            dialog.close();
        }
    ));

    choose_executable_button.connect_clicked({
        let parent = parent.clone();
        let executable_row = executable_row.clone();
        let executable = executable.clone();
        move |_| {
            diagnostics::debug(
                "ui.profile-dialog",
                format_args!("opening executable chooser"),
            );
            let file_dialog = gtk::FileDialog::builder()
                .title("Select Application Executable")
                .modal(true)
                .build();
            let parent = parent.clone();
            let executable_row = executable_row.clone();
            let executable = executable.clone();
            glib::MainContext::default().spawn_local(async move {
                match file_dialog.open_future(Some(&parent)).await {
                    Ok(file) => {
                        if let Some(path) = file.path() {
                            diagnostics::info(
                                "ui.profile-dialog",
                                format_args!("selected an application executable"),
                            );
                            executable_row.set_subtitle(path.to_string_lossy().as_ref());
                            *executable.borrow_mut() = path;
                        } else {
                            diagnostics::warn(
                                "ui.profile-dialog",
                                format_args!("selected executable did not have a local path"),
                            );
                        }
                    }
                    Err(error) => {
                        diagnostics::debug(
                            "ui.profile-dialog",
                            format_args!("executable chooser closed without a selection: {error}"),
                        );
                    }
                }
            });
        }
    });

    add_directory_row.connect_activated({
        let parent = parent.clone();
        let directories_list = directories_list.clone();
        let directories = directories.clone();
        move |_| {
            diagnostics::debug(
                "ui.profile-dialog",
                format_args!("opening protected-directory chooser"),
            );
            let file_dialog = gtk::FileDialog::builder()
                .title("Select Protected Directory")
                .modal(true)
                .build();
            let parent = parent.clone();
            let directories_list = directories_list.clone();
            let directories = directories.clone();
            glib::MainContext::default().spawn_local(async move {
                match file_dialog.select_folder_future(Some(&parent)).await {
                    Ok(file) => {
                        if let Some(path) = file.path() {
                            let mut paths = directories.borrow_mut();
                            if !paths.contains(&path) {
                                paths.push(path);
                                diagnostics::info(
                                    "ui.profile-dialog",
                                    format_args!(
                                        "added a protected directory; total={}",
                                        paths.len()
                                    ),
                                );
                            } else {
                                diagnostics::debug(
                                    "ui.profile-dialog",
                                    format_args!("ignored a duplicate protected directory"),
                                );
                            }
                            drop(paths);
                            refresh_directories(&directories_list, &directories);
                        } else {
                            diagnostics::warn(
                                "ui.profile-dialog",
                                format_args!("selected directory did not have a local path"),
                            );
                        }
                    }
                    Err(error) => diagnostics::debug(
                        "ui.profile-dialog",
                        format_args!("directory chooser closed without a selection: {error}"),
                    ),
                }
            });
        }
    });

    let original_id = profile.id;
    let original_applied = profile.applied;
    let previous_local = (!is_new).then_some(original_profile);
    let collect_profile: Rc<dyn Fn() -> ProtectionProfile> = {
        let executable = executable.clone();
        let directories = directories.clone();
        let name_row = name_row.clone();
        let launch_domain_row = launch_domain_row.clone();
        let launch_role_row = launch_role_row.clone();
        let block_ptrace_row = block_ptrace_row.clone();
        let block_fd_use_row = block_fd_use_row.clone();
        Rc::new(move || ProtectionProfile {
            id: original_id,
            name: name_row.text().trim().to_owned(),
            executable: executable.borrow().clone(),
            data_directories: directories.borrow().clone(),
            launch_domain: launch_domain_row.text().trim().to_owned(),
            launch_role: launch_role_row.text().trim().to_owned(),
            block_ptrace: block_ptrace_row.is_active(),
            block_fd_use: block_fd_use_row.is_active(),
            applied: original_applied,
        })
    };

    preview_policy_row.connect_activated({
        let dialog = dialog.clone();
        let collect_profile = collect_profile.clone();
        move |_| {
            let profile = collect_profile();
            diagnostics::info(
                "ui.profile-dialog",
                format_args!("policy preview requested for profile {}", profile.id),
            );
            match policy::render_preview(&profile) {
                Ok(preview) => {
                    diagnostics::debug(
                        "ui.profile-dialog",
                        format_args!("policy preview rendered successfully"),
                    );
                    text_dialog::present(&dialog, "Policy Preview", &preview);
                }
                Err(error) => {
                    diagnostics::warn(
                        "ui.profile-dialog",
                        format_args!("policy preview validation failed: {error:#}"),
                    );
                    show_error(&dialog, "Cannot Preview Policy", &error.to_string());
                }
            }
        }
    });

    apply_button.connect_clicked({
        let dialog = dialog.clone();
        let toast_overlay = toast_overlay.clone();
        let collect_profile = collect_profile.clone();
        let on_saved = on_saved.clone();
        let previous_local = previous_local.clone();
        move |button| {
            let mut candidate = collect_profile();
            diagnostics::info(
                "ui.profile-dialog",
                format_args!(
                    "apply requested for profile {} with {} protected directorie(s)",
                    candidate.id,
                    candidate.data_directories.len()
                ),
            );
            if let Err(error) = validate_local_paths(&candidate)
                .and_then(|_| policy::validate_profile(&candidate))
            {
                diagnostics::warn(
                    "ui.profile-dialog",
                    format_args!("local profile validation failed: {error:#}"),
                );
                show_error(&dialog, "Cannot Apply Protection", &error.to_string());
                return;
            }

            let mut pending = candidate.clone();
            pending.applied = false;
            if let Err(error) = upsert_profile(pending) {
                diagnostics::error(
                    "ui.profile-dialog",
                    format_args!("could not save pending profile {}: {error:#}", candidate.id),
                );
                show_error(
                    &dialog,
                    "Cannot Save Profile",
                    &format!("No SELinux changes were made: {error}"),
                );
                return;
            }

            button.set_sensitive(false);
            candidate.applied = true;
            let request = HelperRequest::Apply {
                profile: candidate.clone(),
            };
            let (sender, receiver) = async_channel::bounded(1);
            thread::spawn(move || {
                diagnostics::debug(
                    "ui.profile-dialog",
                    format_args!("invoking privileged apply operation"),
                );
                let result = helper_client::invoke(&request);
                if sender.send_blocking(result).is_err() {
                    diagnostics::warn(
                        "ui.profile-dialog",
                        format_args!("apply result receiver was dropped"),
                    );
                }
            });

            let dialog = dialog.clone();
            let button = button.clone();
            let toast_overlay = toast_overlay.clone();
            let on_saved = on_saved.clone();
            let previous_local = previous_local.clone();
            glib::MainContext::default().spawn_local(async move {
                match receiver.recv().await {
                    Ok(Ok(response)) if response.ok => {
                        if let Err(error) = upsert_profile(candidate) {
                            diagnostics::error(
                                "ui.profile-dialog",
                                format_args!(
                                    "protection was applied but local profile save failed: {error:#}"
                                ),
                            );
                            show_error(
                                &dialog,
                                "Protection Applied",
                                &format!(
                                    "SELinux protection was applied, but the local profile could not \
                                     be saved: {error}"
                                ),
                            );
                            button.set_sensitive(true);
                            return;
                        }
                        diagnostics::info(
                            "ui.profile-dialog",
                            format_args!("protection applied successfully to profile {original_id}"),
                        );
                        (on_saved)();
                        toast_overlay.add_toast(adw::Toast::new("Protection applied"));
                        dialog.close();
                    }
                    Ok(Ok(response)) => {
                        diagnostics::error(
                            "ui.profile-dialog",
                            format_args!(
                                "privileged apply failed for profile {original_id}: {}",
                                response.message
                            ),
                        );
                        let body = restore_failure_message(
                            &response.message,
                            restore_local_after_failed_apply(
                                previous_local.as_ref(),
                                original_id,
                            ),
                        );
                        show_error(&dialog, "Cannot Apply Protection", &body);
                        button.set_sensitive(true);
                    }
                    Ok(Err(error)) => {
                        diagnostics::error(
                            "ui.profile-dialog",
                            format_args!(
                                "could not invoke privileged apply for profile {original_id}: \
                                 {error:#}"
                            ),
                        );
                        let body = restore_failure_message(
                            &error.to_string(),
                            restore_local_after_failed_apply(
                                previous_local.as_ref(),
                                original_id,
                            ),
                        );
                        show_error(&dialog, "Cannot Apply Protection", &body);
                        button.set_sensitive(true);
                    }
                    Err(_) => {
                        diagnostics::error(
                            "ui.profile-dialog",
                            format_args!(
                                "privileged apply channel closed for profile {original_id}"
                            ),
                        );
                        let body = restore_failure_message(
                            "The helper stopped unexpectedly",
                            restore_local_after_failed_apply(
                                previous_local.as_ref(),
                                original_id,
                            ),
                        );
                        show_error(&dialog, "Cannot Apply Protection", &body);
                        button.set_sensitive(true);
                    }
                }
            });
        }
    });

    remove_protection_row.connect_activated({
        let dialog = dialog.clone();
        let toast_overlay = toast_overlay.clone();
        let on_saved = on_saved.clone();
        move |_| {
            diagnostics::info(
                "ui.profile-dialog",
                format_args!("remove requested for profile {original_id}"),
            );
            let confirmation = adw::AlertDialog::builder()
                .heading(if original_applied {
                    "Remove Protection?"
                } else {
                    "Delete Profile?"
                })
                .body(if original_applied {
                    "The original SELinux labels will be restored and the generated policy \
                     modules will be removed."
                } else {
                    "Microvisor will check for any interrupted privileged operation, remove it \
                     if present, and delete this local profile."
                })
                .build();
            confirmation.add_response("cancel", "Cancel");
            confirmation.add_response(
                "remove",
                if original_applied { "Remove" } else { "Delete" },
            );
            confirmation
                .set_response_appearance("remove", adw::ResponseAppearance::Destructive);
            confirmation.set_default_response(Some("cancel"));
            confirmation.set_close_response("cancel");

            let dialog_for_response = dialog.clone();
            let toast_for_response = toast_overlay.clone();
            let on_saved_for_response = on_saved.clone();
            confirmation.connect_response(None, move |confirmation, response| {
                if response != "remove" {
                    diagnostics::debug(
                        "ui.profile-dialog",
                        format_args!("remove cancelled for profile {original_id}"),
                    );
                    return;
                }
                diagnostics::info(
                    "ui.profile-dialog",
                    format_args!("remove confirmed for profile {original_id}"),
                );
                confirmation.set_response_enabled("remove", false);
                let request = HelperRequest::Remove { id: original_id };
                let (sender, receiver) = async_channel::bounded(1);
                thread::spawn(move || {
                    diagnostics::debug(
                        "ui.profile-dialog",
                        format_args!("invoking privileged remove operation"),
                    );
                    let result = helper_client::invoke(&request);
                    if sender.send_blocking(result).is_err() {
                        diagnostics::warn(
                            "ui.profile-dialog",
                            format_args!("remove result receiver was dropped"),
                        );
                    }
                });

                let dialog = dialog_for_response.clone();
                let toast_overlay = toast_for_response.clone();
                let on_saved = on_saved_for_response.clone();
                glib::MainContext::default().spawn_local(async move {
                    match receiver.recv().await {
                        Ok(Ok(response)) if response.ok => {
                            if let Err(error) = delete_profile(original_id) {
                                diagnostics::error(
                                    "ui.profile-dialog",
                                    format_args!(
                                        "protection was removed but local profile deletion failed: \
                                         {error:#}"
                                    ),
                                );
                                show_error(
                                    &dialog,
                                    "Protection Removed",
                                    &format!(
                                        "SELinux protection was removed, but the local profile could not \
                                         be deleted: {error}"
                                    ),
                                );
                                return;
                            }
                            diagnostics::info(
                                "ui.profile-dialog",
                                format_args!(
                                    "protection removed successfully from profile {original_id}"
                                ),
                            );
                            (on_saved)();
                            toast_overlay.add_toast(adw::Toast::new(if original_applied {
                                "Protection removed"
                            } else {
                                "Profile deleted"
                            }));
                            dialog.close();
                        }
                        Ok(Ok(response)) => {
                            diagnostics::error(
                                "ui.profile-dialog",
                                format_args!(
                                    "privileged remove failed for profile {original_id}: {}",
                                    response.message
                                ),
                            );
                            show_error(&dialog, "Cannot Remove Protection", &response.message)
                        }
                        Ok(Err(error)) => {
                            diagnostics::error(
                                "ui.profile-dialog",
                                format_args!(
                                    "could not invoke privileged remove for profile {original_id}: \
                                     {error:#}"
                                ),
                            );
                            show_error(&dialog, "Cannot Remove Protection", &error.to_string())
                        }
                        Err(_) => {
                            diagnostics::error(
                                "ui.profile-dialog",
                                format_args!(
                                    "privileged remove channel closed for profile {original_id}"
                                ),
                            );
                            show_error(
                                &dialog,
                                "Cannot Remove Protection",
                                "The helper stopped unexpectedly",
                            );
                        }
                    }
                });
            });
            confirmation.present(Some(&dialog));
        }
    });

    dialog.present(Some(&parent));
}

struct ProfileDialogWidgets {
    dialog: adw::Dialog,
    apply_button: gtk::Button,
    cancel_button: gtk::Button,
    name_row: adw::EntryRow,
    executable_row: adw::ActionRow,
    choose_executable_button: gtk::Button,
    directories_list: gtk::ListBox,
    add_directory_row: adw::ButtonRow,
    launch_domain_row: adw::EntryRow,
    launch_role_row: adw::EntryRow,
    block_ptrace_row: adw::SwitchRow,
    block_fd_use_row: adw::SwitchRow,
    preview_policy_row: adw::ButtonRow,
    remove_group: adw::PreferencesGroup,
    remove_protection_row: adw::ButtonRow,
}

fn build_profile_dialog() -> ProfileDialogWidgets {
    let cancel_button = gtk::Button::builder().label("Cancel").build();
    let apply_button = gtk::Button::builder()
        .label("Apply")
        .css_classes(["suggested-action"])
        .build();
    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_button);
    header.pack_end(&apply_button);

    let name_row = adw::EntryRow::builder().title("Name").build();
    let executable_row = adw::ActionRow::builder()
        .title("Executable")
        .subtitle("Select an executable")
        .build();
    let choose_executable_button = gtk::Button::builder()
        .icon_name("document-open-symbolic")
        .tooltip_text("Choose Executable")
        .valign(gtk::Align::Center)
        .build();
    executable_row.add_suffix(&choose_executable_button);

    let application_group = adw::PreferencesGroup::builder()
        .title("Application")
        .description(
            "Select the final executable that should enter the protected domain. For launcher \
             scripts, select the actual application binary when possible.",
        )
        .build();
    application_group.add(&name_row);
    application_group.add(&executable_row);

    let directories_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let add_directory_row = adw::ButtonRow::builder()
        .title("Add Directory")
        .start_icon_name("list-add-symbolic")
        .build();
    let directories_group = adw::PreferencesGroup::builder()
        .title("Protected Directories")
        .description(
            "All files below these directories receive a profile-specific SELinux data type.",
        )
        .build();
    directories_group.add(&directories_list);
    directories_group.add(&add_directory_row);

    let launch_domain_row = adw::EntryRow::builder()
        .title("Launch Domain")
        .text("unconfined_t")
        .build();
    let launch_role_row = adw::EntryRow::builder()
        .title("Launch Role")
        .text("unconfined_r")
        .build();
    let block_ptrace_row = adw::SwitchRow::builder()
        .title("Block Process Inspection")
        .subtitle("Remove ptrace access to the protected application from every other type.")
        .active(true)
        .build();
    let block_fd_use_row = adw::SwitchRow::builder()
        .title("Block Foreign File Descriptor Use")
        .subtitle(
            "Stronger isolation that can disrupt portals, crash handlers, and desktop \
             integration.",
        )
        .active(false)
        .build();
    let preview_policy_row = adw::ButtonRow::builder()
        .title("Preview Policy")
        .start_icon_name("text-x-generic-symbolic")
        .build();
    let domain_group = adw::PreferencesGroup::builder()
        .title("SELinux Domain")
        .description("The defaults match a typical Fedora Workstation session using unconfined_u.")
        .build();
    domain_group.add(&launch_domain_row);
    domain_group.add(&launch_role_row);
    domain_group.add(&block_ptrace_row);
    domain_group.add(&block_fd_use_row);
    domain_group.add(&preview_policy_row);

    let remove_protection_row = adw::ButtonRow::builder()
        .title("Remove Protection")
        .start_icon_name("edit-delete-symbolic")
        .css_classes(["destructive-action"])
        .build();
    let remove_group = adw::PreferencesGroup::builder().title("Remove").build();
    remove_group.add(&remove_protection_row);

    let page = adw::PreferencesPage::new();
    page.add(&application_group);
    page.add(&directories_group);
    page.add(&domain_group);
    page.add(&remove_group);

    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&page)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&scrolled));
    let dialog = adw::Dialog::builder()
        .title("Application Protection")
        .content_width(640)
        .content_height(720)
        .child(&toolbar)
        .build();

    ProfileDialogWidgets {
        dialog,
        apply_button,
        cancel_button,
        name_row,
        executable_row,
        choose_executable_button,
        directories_list,
        add_directory_row,
        launch_domain_row,
        launch_role_row,
        block_ptrace_row,
        block_fd_use_row,
        preview_policy_row,
        remove_group,
        remove_protection_row,
    }
}

fn refresh_directories(list: &gtk::ListBox, directories: &Rc<RefCell<Vec<PathBuf>>>) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    for path in directories.borrow().iter().cloned() {
        let title = path.to_string_lossy().into_owned();
        let row = adw::ActionRow::builder().title(&title).build();
        let remove = gtk::Button::builder()
            .icon_name("edit-delete-symbolic")
            .tooltip_text("Remove Directory")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        row.add_suffix(&remove);
        list.append(&row);

        let list = list.clone();
        let directories = directories.clone();
        remove.connect_clicked(move |_| {
            directories
                .borrow_mut()
                .retain(|candidate| candidate != &path);
            diagnostics::info(
                "ui.profile-dialog",
                format_args!(
                    "removed a protected directory; total={}",
                    directories.borrow().len()
                ),
            );
            refresh_directories(&list, &directories);
        });
    }
}

fn validate_local_paths(profile: &ProtectionProfile) -> Result<()> {
    if !profile.executable.is_file() {
        anyhow::bail!("The selected executable does not exist or is not a regular file");
    }
    for directory in &profile.data_directories {
        if !directory.is_dir() {
            anyhow::bail!("{} is not an existing directory", directory.display());
        }
    }
    Ok(())
}

fn restore_local_after_failed_apply(
    previous: Option<&ProtectionProfile>,
    id: uuid::Uuid,
) -> Result<()> {
    match previous {
        Some(profile) => upsert_profile(profile.clone()),
        None => delete_profile(id),
    }
}

fn restore_failure_message(message: &str, restore: Result<()>) -> String {
    match restore {
        Ok(()) => message.to_owned(),
        Err(error) => {
            format!("{message}\n\nThe previous local profile state could not be restored: {error}")
        }
    }
}

fn upsert_profile(profile: ProtectionProfile) -> Result<()> {
    let mut profiles = storage::load_profiles()?;
    if let Some(existing) = profiles.iter_mut().find(|item| item.id == profile.id) {
        *existing = profile;
    } else {
        profiles.push(profile);
    }
    storage::save_profiles(&profiles)
}

fn delete_profile(id: uuid::Uuid) -> Result<()> {
    let mut profiles = storage::load_profiles()?;
    profiles.retain(|profile| profile.id != id);
    storage::save_profiles(&profiles)
}

fn show_error(parent: &impl IsA<gtk::Widget>, heading: &str, body: &str) {
    diagnostics::debug(
        "ui.profile-dialog",
        format_args!("presenting error dialog {heading:?}"),
    );
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("close", "Close");
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");
    dialog.present(Some(parent));
}
