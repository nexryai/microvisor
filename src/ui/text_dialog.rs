use adw::prelude::*;
use gtk::gdk;

pub fn present(parent: &impl IsA<gtk::Widget>, title: &str, text: &str) {
    let dialog = adw::Dialog::builder()
        .title(title)
        .content_width(760)
        .content_height(640)
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy")
        .build();
    header.pack_end(&copy_button);
    toolbar.add_top_bar(&header);

    let buffer = gtk::TextBuffer::builder().text(text).build();
    let text_view = gtk::TextView::builder()
        .buffer(&buffer)
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .left_margin(12)
        .right_margin(12)
        .top_margin(12)
        .bottom_margin(12)
        .wrap_mode(gtk::WrapMode::None)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .child(&text_view)
        .build();
    toolbar.set_content(Some(&scrolled));
    dialog.set_child(Some(&toolbar));

    let copied_text = text.to_owned();
    copy_button.connect_clicked(move |_| {
        if let Some(display) = gdk::Display::default() {
            display.clipboard().set_text(&copied_text);
        }
    });

    dialog.present(Some(parent));
}
