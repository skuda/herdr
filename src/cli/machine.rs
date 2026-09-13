use serde::Serialize;

use crate::client::endpoint::{AddProfileError, CatalogUpdateError, EndpointCatalog, ProfileId};

const HELP: &str = "Usage:
  herdr machine list [--json]
  herdr machine add <ssh-target> --label <label> [--remote-session <name>]
  herdr machine rename <profile-id> --label <label>
  herdr machine remove <profile-id>
  herdr machine enable <profile-id>
  herdr machine disable <profile-id>
  herdr machine availability <profile-id> --local-session <name> [--local-session <name> ...]
  herdr machine availability <profile-id> --all-local-sessions
  herdr machine availability <profile-id> --no-local-sessions

Add prepares the remote Herdr installation and starts its server before saving.
Missing or incompatible installations require approval in an interactive terminal.
Changes apply automatically to open local Herdr clients.
Removing or disabling a machine leaves its remote sessions running.
Availability limits which local sessions can use a saved machine.
List columns are id, label, target, session, enabled, availability, available, and selected.
Availability is all, none, or the allowed local session names.
Available and selected are for the current local session.
Saved machines contain only a label, SSH target, explicit Herdr session, enabled state, and optional local-session list.
SSH credentials and key material remain owned by OpenSSH.";

#[derive(Serialize)]
struct MachineListRow<'a> {
    id: &'a str,
    label: &'a str,
    target: &'a str,
    session: &'a str,
    enabled: bool,
    selected: bool,
    local_sessions: Option<&'a [String]>,
    available: bool,
}

pub(super) fn run_machine_command(args: &[String]) -> std::io::Result<i32> {
    match args.first().map(String::as_str) {
        Some("list") => list(&args[1..]),
        Some("add") => add(&args[1..]),
        Some("rename") => rename(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("enable") => set_enabled(&args[1..], true),
        Some("disable") => set_enabled(&args[1..], false),
        Some("availability") => set_availability(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            Ok(0)
        }
        _ => {
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn list(args: &[String]) -> std::io::Result<i32> {
    let json = match args {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => {
            eprintln!("usage: herdr machine list [--json]");
            return Ok(2);
        }
    };
    let catalog = load_raw_catalog()?;
    let local_session = crate::session::validated_local_session_name()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let selected = catalog.selected_profile_for_local_session(&local_session);
    let rows = catalog
        .ssh
        .iter()
        .map(|profile| MachineListRow {
            id: profile.id.as_str(),
            label: &profile.label,
            target: &profile.target,
            session: &profile.session,
            enabled: profile.enabled,
            selected: selected.as_ref() == Some(&profile.id),
            local_sessions: profile.local_sessions.as_deref(),
            available: profile.is_available_in(&local_session),
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
        return Ok(0);
    }
    if rows.is_empty() {
        println!("No saved SSH machines.");
        return Ok(0);
    }
    for row in rows {
        let state = if row.enabled { "enabled" } else { "disabled" };
        let availability = match row.local_sessions {
            None => "all".to_owned(),
            Some([]) => "none".to_owned(),
            Some(names) => names.join(","),
        };
        let available = if row.available {
            "available"
        } else {
            "unavailable"
        };
        let selected = if row.selected {
            "selected"
        } else {
            "unselected"
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.id, row.label, row.target, row.session, state, availability, available, selected
        );
    }
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    target: String,
    label: String,
    session: String,
}

fn parse_add_args(args: &[String]) -> Result<AddArgs, String> {
    let args = super::expand_equals_args(args, &["--label", "--remote-session"]);
    let mut target = None;
    let mut label = None;
    let mut session = None;
    let mut index = 0;
    while index < args.len() {
        let (name, value) = match args[index].as_str() {
            "--label" | "--remote-session" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(format!("missing value for {}", args[index]));
                };
                index += 2;
                (args[index - 2].as_str(), value.clone())
            }
            positional if !positional.starts_with('-') && target.is_none() => {
                target = Some(positional.to_owned());
                index += 1;
                continue;
            }
            unknown => {
                return Err(format!("unknown machine add option: {unknown}"));
            }
        };
        match name {
            "--label" if label.is_none() => label = Some(value),
            "--remote-session" if session.is_none() => session = Some(value),
            "--remote-session" => {
                return Err("--remote-session can only be specified once".into());
            }
            "--label" => {
                return Err("--label can only be specified once".into());
            }
            _ => unreachable!("validated machine add option"),
        }
    }
    let target = target.ok_or_else(|| {
        "usage: herdr machine add <ssh-target> --label <label> [--remote-session <name>]".to_owned()
    })?;
    let label = label.ok_or_else(|| "--label is required".to_owned())?;
    let session = session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned());
    Ok(AddArgs {
        target,
        label,
        session,
    })
}

fn add(args: &[String]) -> std::io::Result<i32> {
    let AddArgs {
        target,
        label,
        session,
    } = match parse_add_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let id = match EndpointCatalog::add_profile_after_prepare(
        label,
        target.clone(),
        session,
        crate::remote::prepare_saved_ssh,
    ) {
        Ok(id) => id,
        Err(AddProfileError::Invalid(error)) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
        Err(AddProfileError::Prepare(error)) => {
            eprintln!("error: {error}; machine was not saved");
            crate::remote::print_saved_ssh_error_hint(&error, &target);
            return Ok(1);
        }
        Err(AddProfileError::Load(error)) => return Err(std::io::Error::other(error)),
        Err(AddProfileError::Save(error)) => {
            return Err(std::io::Error::other(format!(
                "remote prepared, but machine was not saved: {error}"
            )));
        }
    };
    println!("Saved SSH machine {id}. Remote server is ready.");
    println!("Open Herdr clients connect automatically.");
    Ok(0)
}

fn rename(args: &[String]) -> std::io::Result<i32> {
    let args = super::expand_equals_args(args, &["--label"]);
    let [raw_id, flag, label] = args.as_slice() else {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    };
    if flag != "--label" {
        eprintln!("usage: herdr machine rename <profile-id> --label <label>");
        return Ok(2);
    }
    let id = match ProfileId::parse(raw_id.clone()) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
    match EndpointCatalog::update_profiles(|catalog| match catalog.rename_ssh(&id, label) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("machine profile {id} was not found")),
        Err(error) => Err(error),
    }) {
        Ok(()) => {}
        Err(error) => return map_update_error(error),
    }
    println!("Renamed SSH machine {id}.");
    Ok(0)
}

fn remove(args: &[String]) -> std::io::Result<i32> {
    let Some(id) = one_profile_id(args, "usage: herdr machine remove <profile-id>")? else {
        return Ok(2);
    };
    match EndpointCatalog::update_profiles(|catalog| {
        if catalog.remove_ssh(&id) {
            Ok(())
        } else {
            Err(format!("machine profile {id} was not found"))
        }
    }) {
        Ok(()) => {}
        Err(error) => return map_update_error(error),
    }
    println!("Removed SSH machine {id}.");
    Ok(0)
}

fn set_enabled(args: &[String], enabled: bool) -> std::io::Result<i32> {
    let action = if enabled { "enable" } else { "disable" };
    let usage = format!("usage: herdr machine {action} <profile-id>");
    let Some(id) = one_profile_id(args, &usage)? else {
        return Ok(2);
    };
    match EndpointCatalog::update_profiles(|catalog| {
        if catalog.set_enabled(&id, enabled) {
            Ok(())
        } else {
            Err(format!("machine profile {id} was not found"))
        }
    }) {
        Ok(()) => {}
        Err(error) => return map_update_error(error),
    }
    println!(
        "{} SSH machine {id}.",
        if enabled { "Enabled" } else { "Disabled" }
    );
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
enum AvailabilityArgs {
    Sessions(Vec<String>),
    All,
    None,
}

fn parse_availability_args(args: &[String]) -> Result<(ProfileId, AvailabilityArgs), String> {
    let usage = "usage: herdr machine availability <profile-id> --local-session <name> [--local-session <name> ...] | --all-local-sessions | --no-local-sessions";
    let Some((raw_id, rest)) = args.split_first() else {
        return Err(usage.into());
    };
    if raw_id.starts_with('-') {
        return Err(usage.into());
    }
    let id = ProfileId::parse(raw_id.clone())?;
    let mut sessions = Vec::new();
    let mut all = false;
    let mut none = false;
    let mut index = 0;
    while index < rest.len() {
        let arg = rest[index].as_str();
        if let Some(value) = arg.strip_prefix("--local-session=") {
            crate::session::validate_name(value)?;
            sessions.push(value.to_string());
            index += 1;
            continue;
        }
        match arg {
            "--local-session" => {
                let Some(value) = rest.get(index + 1) else {
                    return Err("missing value for --local-session".into());
                };
                if value.starts_with('-') {
                    return Err("missing value for --local-session".into());
                }
                crate::session::validate_name(value)?;
                sessions.push(value.clone());
                index += 2;
            }
            "--all-local-sessions" if !all => {
                all = true;
                index += 1;
            }
            "--no-local-sessions" if !none => {
                none = true;
                index += 1;
            }
            "--all-local-sessions" | "--no-local-sessions" => {
                return Err(format!("{arg} can only be specified once"));
            }
            unknown => return Err(format!("unknown machine availability option: {unknown}")),
        }
    }
    let form_count = usize::from(!sessions.is_empty()) + usize::from(all) + usize::from(none);
    let availability = match (sessions.is_empty(), all, none, form_count) {
        (false, false, false, 1) => AvailabilityArgs::Sessions(sessions),
        (true, true, false, 1) => AvailabilityArgs::All,
        (true, false, true, 1) => AvailabilityArgs::None,
        _ => return Err(usage.into()),
    };
    Ok((id, availability))
}

fn set_availability(args: &[String]) -> std::io::Result<i32> {
    let (id, availability) = match parse_availability_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    let local_sessions = match availability {
        AvailabilityArgs::All => None,
        AvailabilityArgs::None => Some(Vec::new()),
        AvailabilityArgs::Sessions(names) => Some(names),
    };
    match EndpointCatalog::update_profiles(|catalog| {
        match catalog.set_local_sessions(&id, local_sessions) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!("machine profile {id} was not found")),
            Err(error) => Err(error),
        }
    }) {
        Ok(()) => {}
        Err(error) => return map_update_error(error),
    }
    println!("Updated SSH machine {id} availability.");
    Ok(0)
}

fn one_profile_id(args: &[String], usage: &str) -> std::io::Result<Option<ProfileId>> {
    let [raw] = args else {
        eprintln!("{usage}");
        return Ok(None);
    };
    match ProfileId::parse(raw.clone()) {
        Ok(id) => Ok(Some(id)),
        Err(error) => {
            eprintln!("error: {error}");
            Ok(None)
        }
    }
}

fn load_raw_catalog() -> std::io::Result<EndpointCatalog> {
    EndpointCatalog::load_raw().map_err(std::io::Error::other)
}

fn map_update_error(error: CatalogUpdateError) -> std::io::Result<i32> {
    match error {
        CatalogUpdateError::Mutation(error) if error.contains("was not found") => {
            eprintln!("{error}");
            Ok(1)
        }
        CatalogUpdateError::Mutation(error) => {
            eprintln!("error: {error}");
            Ok(2)
        }
        CatalogUpdateError::Storage(error) => Err(std::io::Error::other(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parser_preserves_values_across_argument_orders() {
        for (args, session) in [
            (vec!["--label", "coder", "workstation.coder"], "default"),
            (vec!["workstation.coder", "--label", "coder"], "default"),
            (
                vec![
                    "--remote-session",
                    "agents",
                    "workstation.coder",
                    "--label",
                    "coder",
                ],
                "agents",
            ),
            (
                vec![
                    "--label=coder",
                    "--remote-session=agents",
                    "workstation.coder",
                ],
                "agents",
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse_add_args(&args).unwrap(),
                AddArgs {
                    target: "workstation.coder".into(),
                    label: "coder".into(),
                    session: session.into(),
                },
                "{args:?}"
            );
        }
    }

    #[test]
    fn add_parser_rejects_incomplete_duplicate_and_extra_arguments() {
        for args in [
            vec![],
            vec!["--label", "coder"],
            vec!["workstation.coder"],
            vec!["workstation.coder", "--label"],
            vec!["workstation.coder", "--label", "coder", "--remote-session"],
            vec!["--label", "coder", "--label", "other", "workstation.coder"],
            vec![
                "workstation.coder",
                "--label",
                "coder",
                "--remote-session",
                "a",
                "--remote-session",
                "b",
            ],
            vec!["--label", "coder", "workstation.coder", "other-host"],
            vec!["--unknown", "workstation.coder", "--label", "coder"],
            vec!["--label", "--remote-session", "agents", "workstation.coder"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(parse_add_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn profile_id_parser_rejects_target_text() {
        assert!(one_profile_id(&["build.example".into()], "usage")
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_rows_do_not_have_credential_fields() {
        let encoded = serde_json::to_string(&MachineListRow {
            id: "0123456789abcdef0123456789abcdef",
            label: "Build",
            target: "dev@build",
            session: "agents",
            enabled: true,
            selected: false,
            local_sessions: None,
            available: true,
        })
        .unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("key"));
        assert!(encoded.contains("local_sessions"));
        assert!(encoded.contains("available"));
    }

    #[test]
    fn availability_parser_matches_spec() {
        let id = "0123456789abcdef0123456789abcdef";
        let cases: &[(&[&str], bool)] = &[
            (
                &[
                    id,
                    "--local-session",
                    "default",
                    "--local-session=tradingdroid",
                ],
                true,
            ),
            (&[id, "--all-local-sessions"], true),
            (&[id, "--no-local-sessions"], true),
            (&[id, "--local-session=-dev"], true),
            (&[id, "--local-session", "--all-local-sessions"], false),
            (&[id, "--local-session", "--no-local-sessions"], false),
            (&[id, "--local-session", "-dev"], false),
            (&[id, "--all-local-sessions", "--no-local-sessions"], false),
            (&[id, "--all-local-sessions", "--all-local-sessions"], false),
            (&[id, "--no-local-sessions", "--no-local-sessions"], false),
            (
                &[id, "--all-local-sessions", "--local-session", "default"],
                false,
            ),
            (&[id, "--local-session", "bad/name"], false),
            (&[id], false),
            (&[id, "--local-session"], false),
            (&["Build", "--all-local-sessions"], false),
            (&[id, "--all-local-sessions", "extra"], false),
            (&["--all-local-sessions"], false),
        ];
        for (args, accepted) in cases {
            let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            let runtime = parse_availability_args(&owned);
            let mut spec_args = vec![
                "herdr".to_string(),
                "machine".to_string(),
                "availability".to_string(),
            ];
            spec_args.extend(owned.clone());
            let spec = crate::cli::spec_command().try_get_matches_from(spec_args);
            assert_eq!(runtime.is_ok(), *accepted, "runtime {args:?}");
            assert_eq!(spec.is_ok(), *accepted, "spec {args:?}");
        }
        assert_eq!(
            parse_availability_args(&[id.into(), "--local-session=-dev".into()])
                .unwrap()
                .1,
            AvailabilityArgs::Sessions(vec!["-dev".into()])
        );
    }
}
