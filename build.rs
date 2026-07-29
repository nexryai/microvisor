fn main() {
    if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
        glib_build_tools::compile_resources(
            &["data"],
            "data/resources.gresource.xml",
            "microvisor.gresource",
        );
    }
}
