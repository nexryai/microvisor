use adw::prelude::*;

pub fn present(parent: &impl IsA<gtk::Widget>) {
    let section = adw::ShortcutsSection::new(Some("General"));
    section.add(adw::ShortcutsItem::from_action(
        "Add Application",
        "win.add-profile",
    ));
    section.add(adw::ShortcutsItem::from_action(
        "Show Shortcuts",
        "app.shortcuts",
    ));
    section.add(adw::ShortcutsItem::from_action("Quit", "app.quit"));

    let dialog = adw::ShortcutsDialog::new();
    dialog.add(section);
    dialog.present(Some(parent));
}
