use std::fmt;

pub fn debug(target: &str, message: fmt::Arguments<'_>) {
    write("DEBUG", target, message);
}

pub fn info(target: &str, message: fmt::Arguments<'_>) {
    write("INFO", target, message);
}

pub fn warn(target: &str, message: fmt::Arguments<'_>) {
    write("WARN", target, message);
}

pub fn error(target: &str, message: fmt::Arguments<'_>) {
    write("ERROR", target, message);
}

fn write(level: &str, target: &str, message: fmt::Arguments<'_>) {
    eprintln!(
        "microvisor[{}] {level} {target}: {message}",
        std::process::id()
    );
}
