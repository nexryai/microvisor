use anyhow::{Context, Result, bail};
use microvisor::{config, diagnostics, engine, policy, supervise, template};
use std::{env, path::Path};
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXIT_ERROR: i32 = 1;
const EXIT_DRIFT: i32 = 2;

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            diagnostics::error("cli", format_args!("{error:#}"));
            std::process::exit(EXIT_ERROR);
        }
    }
}

fn run() -> Result<i32> {
    let arguments = env::args_os()
        .skip(1)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| anyhow::anyhow!("Command arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;

    match arguments.as_slice() {
        [] => {
            print_help();
            return Ok(0);
        }
        [command] if command == "help" || command == "--help" || command == "-h" => {
            print_help();
            return Ok(0);
        }
        [command] if command == "version" || command == "--version" || command == "-V" => {
            println!("microvisor {VERSION}");
            return Ok(0);
        }
        [command, rest @ ..] if command == "generate" => {
            return generate_template(rest);
        }
        _ => {}
    }

    engine::require_root()?;
    match arguments.as_slice() {
        [command] if command == "validate" => {
            let profiles = load_and_validate()?;
            println!("Validated {} profile(s).", profiles.len());
            Ok(0)
        }
        [command, id] if command == "render" => {
            let id = parse_id(id)?;
            let profiles = load_and_validate()?;
            let profile = profiles
                .iter()
                .find(|profile| profile.id == id)
                .with_context(|| format!("No configured profile exists for {id}"))?;
            print!("{}", policy::render_preview(profile)?);
            Ok(0)
        }
        [command] if command == "apply" => {
            let profiles = config::load_profiles(Path::new(config::DEFAULT_CONFIG_DIR))?;
            let count = engine::apply_profiles(profiles)?;
            println!("Applied {count} changed profile(s).");
            Ok(0)
        }
        [command] if command == "status" => {
            let profiles = config::load_profiles(Path::new(config::DEFAULT_CONFIG_DIR))?;
            let (statuses, converged) = engine::status(profiles)?;
            if statuses.is_empty() {
                println!("No configured or applied profiles.");
            } else {
                for status in statuses {
                    println!("{}\t{}\t{}", status.id, status.state, status.name);
                }
            }
            Ok(if converged { 0 } else { EXIT_DRIFT })
        }
        [command] if command == "supervise" => {
            let profiles = config::load_profiles(Path::new(config::DEFAULT_CONFIG_DIR))?;
            let profiles = engine::supervision_profiles(profiles)?;
            supervise::run(&profiles)?;
            Ok(0)
        }
        [command, id] if command == "remove" => {
            let id = parse_id(id)?;
            if engine::remove_profile(id)? {
                println!("Removed profile {id}.");
            } else {
                println!("Profile {id} is not applied.");
            }
            Ok(0)
        }
        _ => {
            bail!("Invalid command. Run 'microvisor help' for usage")
        }
    }
}

fn generate_template(arguments: &[String]) -> Result<i32> {
    let id = Uuid::new_v4();
    let path = match arguments {
        [] => template::default_path(id),
        [path] => path.into(),
        _ => bail!("Usage: microvisor generate [output.yaml]"),
    };
    template::write_new(&path, id)?;
    println!("Generated {} with profile ID {id}.", path.display());
    Ok(0)
}

fn load_and_validate() -> Result<Vec<microvisor::model::ProtectionProfile>> {
    let profiles = config::load_profiles(Path::new(config::DEFAULT_CONFIG_DIR))?;
    engine::validate_desired_profiles(profiles)
}

fn parse_id(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).with_context(|| format!("Invalid profile ID '{value}'"))
}

fn print_help() {
    println!(
        "Microvisor {VERSION}\n\
         Headless SELinux protection profile manager\n\n\
         Usage:\n\
           microvisor validate\n\
           microvisor render <profile-id>\n\
           microvisor apply\n\
           microvisor status\n\
           microvisor supervise\n\
           microvisor remove <profile-id>\n\
           microvisor generate [output.yaml]\n\
           microvisor help\n\
           microvisor version\n\n\
         Configuration: {}/*.yaml\n\
         Generate, help, and version do not require root. All other commands do.",
        config::DEFAULT_CONFIG_DIR
    );
}
