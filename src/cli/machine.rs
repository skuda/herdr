use std::io::IsTerminal as _;

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, SetAttribute};
use crossterm::{cursor, execute, terminal};
use serde::Serialize;

use crate::client::endpoint::{
    AddProfileError, CatalogUpdateError, EndpointCatalog, ProfileId, MAX_LABEL_BYTES,
};

const HELP: &str = "Usage:
  herdr machine list [--json]
  herdr machine status [<label-or-id>] [--json]
  herdr machine reconnect <label-or-id>
  herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]
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
        Some("status") => status(&args[1..]),
        Some("reconnect") => reconnect(&args[1..]),
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
    let local_session = match crate::session::validated_local_session_name() {
        Ok(name) => name,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(2);
        }
    };
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

#[derive(Serialize)]
struct MachineStatusRow<'a> {
    id: &'a str,
    label: &'a str,
    status: &'static str,
    error: Option<String>,
}

fn status(args: &[String]) -> std::io::Result<i32> {
    let mut json = false;
    let mut selector = None;
    for arg in args {
        if arg == "--json" && !json {
            json = true;
        } else if !arg.starts_with('-') && selector.is_none() {
            selector = Some(arg.as_str());
        } else {
            eprintln!("usage: herdr machine status [<label-or-id>] [--json]");
            return Ok(2);
        }
    }
    let catalog = load_raw_catalog()?;
    let profiles = match selector {
        Some(selector) => match super::target::resolve_machine(&catalog.ssh, selector) {
            Ok(profile) => vec![profile],
            Err(error) => {
                eprintln!("{error}");
                return Ok(2);
            }
        },
        None => catalog.ssh.iter().collect(),
    };
    let rows = profiles
        .into_iter()
        .map(|profile| {
            let (status, error) = if !profile.enabled {
                ("disabled", None)
            } else {
                match crate::remote::check_saved_ssh(&profile.target, &profile.session) {
                    Ok(()) => ("reachable", None),
                    Err(error) => {
                        let message = error.to_string();
                        let status = if crate::remote::ssh_error_requires_authentication(&message) {
                            "auth required"
                        } else {
                            "error"
                        };
                        (status, Some(message))
                    }
                }
            };
            MachineStatusRow {
                id: profile.id.as_str(),
                label: &profile.label,
                status,
                error,
            }
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?
        );
    } else {
        for row in &rows {
            println!("{}\t{}\t{}", row.id, row.label, row.status);
            if let Some(error) = &row.error {
                println!("  {}", error.escape_debug());
            }
        }
        if rows.is_empty() {
            println!("No saved SSH machines.");
        }
    }
    Ok(i32::from(rows.iter().any(|row| row.error.is_some())))
}

fn reconnect(args: &[String]) -> std::io::Result<i32> {
    use std::io::IsTerminal;
    let [selector] = args else {
        eprintln!("usage: herdr machine reconnect <label-or-id>");
        return Ok(2);
    };
    let catalog = load_raw_catalog()?;
    let profile = match super::target::resolve_machine(&catalog.ssh, selector) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("{error}");
            return Ok(2);
        }
    };
    if !std::io::stdin().is_terminal() {
        eprintln!("reconnect requires an interactive terminal; use herdr machine status for noninteractive checks");
        return Ok(2);
    }
    let mut authentication = crate::remote::ssh_authentication_command(&profile.target)?;
    if !authentication.command.status()?.success() {
        eprintln!("SSH authentication failed; the saved machine was not changed.");
        return Ok(1);
    }
    crate::remote::check_saved_ssh(&profile.target, &profile.session)?;
    println!(
        "Machine {} is reachable. Open Herdr clients retry within 30 seconds.",
        profile.id
    );
    Ok(0)
}

#[derive(Debug, PartialEq, Eq)]
struct AddArgs {
    target: String,
    label: Option<String>,
    session: Option<String>,
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
        "usage: herdr machine add <ssh-target> [--label <label>] [--remote-session <name>]"
            .to_owned()
    })?;
    Ok(AddArgs {
        target,
        label,
        session,
    })
}

/// Names the machine after the SSH host, plus the session when it is not the default.
fn default_label(target: &str, session: &str) -> String {
    let url = target
        .strip_prefix("ssh://")
        .map(|authority| authority.trim_end_matches('/'));
    let authority = url.unwrap_or(target);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match (url, host.strip_prefix('[')) {
        (Some(_), Some(bracketed)) => bracketed.split_once(']').map_or(host, |(ip, _)| ip),
        (Some(_), None) => host.split_once(':').map_or(host, |(host, _)| host),
        (None, _) => host,
    };
    if session == crate::session::DEFAULT_SESSION_NAME {
        host.to_owned()
    } else {
        format!("{host}/{session}")
    }
}

fn check_default_label(catalog: &EndpointCatalog, label: &str) -> Result<(), String> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(format!(
            "default machine name '{label}' is longer than {MAX_LABEL_BYTES} bytes; pass --label to choose a name"
        ));
    }
    if catalog.ssh.iter().any(|profile| profile.label == label) {
        return Err(format!(
            "a machine named '{label}' already exists; pass --label to choose another name"
        ));
    }
    Ok(())
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
    let mut setup = None;
    let session =
        if session.is_none() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            let discovered = (|| {
                let connection = crate::remote::SavedSshSetup::connect(&target)?;
                let sessions = connection.running_sessions()?;
                let session = select_remote_session(&sessions, &target)?;
                setup = Some(connection);
                Ok::<_, std::io::Error>(session)
            })();
            match discovered {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("error: {error}; machine was not saved");
                    crate::remote::print_saved_ssh_error_hint(&error, &target);
                    return Ok(1);
                }
            }
        } else {
            session.unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.to_owned())
        };
    let label_is_default = label.is_none();
    let label = label.unwrap_or_else(|| default_label(&target, &session));
    let check = |catalog: &EndpointCatalog| {
        if label_is_default {
            check_default_label(catalog, &label)
        } else {
            Ok(())
        }
    };
    let (id, metadata) = match EndpointCatalog::add_profile_after_prepare(
        label.clone(),
        target.clone(),
        session.clone(),
        check,
        |target, session| {
            setup
                .map(Ok)
                .unwrap_or_else(|| crate::remote::SavedSshSetup::connect(target))
                .and_then(|setup| setup.prepare(session))
        },
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
    if let Some(metadata) = metadata {
        crate::client::endpoint::SshMetadataCache::new(id.as_str(), &target, &session)?
            .store(&metadata);
    }
    println!("Saved SSH machine {id}. Remote server is ready.");
    println!("Open Herdr clients connect automatically.");
    Ok(0)
}

fn select_remote_session(sessions: &[String], target: &str) -> std::io::Result<String> {
    match sessions {
        [] => return Ok(crate::session::DEFAULT_SESSION_NAME.to_owned()),
        [session] => return Ok(session.clone()),
        _ => {}
    }

    let _raw_mode = RawModeGuard::enable()?;
    let mut output = std::io::stderr();
    let mut selected = 0;
    render_remote_session_picker(&mut output, target, sessions, selected, false)?;
    loop {
        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        match key.code {
            KeyCode::Up => selected = selected.checked_sub(1).unwrap_or(sessions.len() - 1),
            KeyCode::Down => selected = (selected + 1) % sessions.len(),
            KeyCode::Enter => return Ok(sessions[selected].clone()),
            KeyCode::Esc => break,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
            _ => continue,
        }
        render_remote_session_picker(&mut output, target, sessions, selected, true)?;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "remote session selection cancelled",
    ))
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn render_remote_session_picker(
    output: &mut impl std::io::Write,
    target: &str,
    sessions: &[String],
    selected: usize,
    redraw: bool,
) -> std::io::Result<()> {
    if redraw {
        execute!(output, cursor::MoveUp((sessions.len() + 2) as u16))?;
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "Running sessions on {target}:\r\n")?;
    for (index, session) in sessions.iter().enumerate() {
        execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
        if index == selected {
            execute!(output, SetAttribute(Attribute::Bold))?;
            write!(output, "> {session}")?;
            execute!(output, SetAttribute(Attribute::Reset))?;
            write!(output, "\r\n")?;
        } else {
            write!(output, "  {session}\r\n")?;
        }
    }
    execute!(output, terminal::Clear(terminal::ClearType::CurrentLine))?;
    write!(output, "↑/↓ select · Enter confirm · Esc cancel\r\n")?;
    output.flush()
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
    let removed = match EndpointCatalog::update_profiles(|catalog| {
        let removed = catalog
            .ssh
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| (profile.target.clone(), profile.session.clone()));
        if catalog.remove_ssh(&id) {
            Ok(removed)
        } else {
            Err(format!("machine profile {id} was not found"))
        }
    }) {
        Ok(removed) => removed,
        Err(error) => return map_update_error(error),
    };
    if let Some((target, session)) = removed {
        crate::client::endpoint::SshMetadataCache::new(id.as_str(), &target, &session)?
            .invalidate();
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
    let usage = "usage: herdr machine availability <profile-id> (--local-session <name> [--local-session <name> ...] | --all-local-sessions | --no-local-sessions)";
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
    let availability = match (sessions.is_empty(), all, none) {
        (false, false, false) => AvailabilityArgs::Sessions(sessions),
        (true, true, false) => AvailabilityArgs::All,
        (true, false, true) => AvailabilityArgs::None,
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
            (vec!["--label", "coder", "workstation.coder"], None),
            (vec!["workstation.coder", "--label", "coder"], None),
            (
                vec![
                    "--remote-session",
                    "agents",
                    "workstation.coder",
                    "--label",
                    "coder",
                ],
                Some("agents"),
            ),
            (
                vec![
                    "--label=coder",
                    "--remote-session=agents",
                    "workstation.coder",
                ],
                Some("agents"),
            ),
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                parse_add_args(&args).unwrap(),
                AddArgs {
                    target: "workstation.coder".into(),
                    label: Some("coder".into()),
                    session: session.map(str::to_owned),
                },
                "{args:?}"
            );
        }
    }

    #[test]
    fn add_parser_leaves_label_unset_without_flag() {
        let parsed = parse_add_args(&["workstation.coder".to_owned()]).unwrap();
        assert_eq!(parsed.label, None);
        assert_eq!(parsed.session, None);
    }

    #[test]
    fn default_label_uses_ssh_host_and_non_default_session() {
        for (target, session, label) in [
            ("workbox", "default", "workbox"),
            ("dev@workbox", "default", "workbox"),
            ("workbox", "agents", "workbox/agents"),
            ("ssh://workbox", "default", "workbox"),
            ("ssh://dev@workbox:2222", "default", "workbox"),
            ("ssh://dev@[::1]:2222", "agents", "::1/agents"),
            ("ssh://dev@workbox/", "default", "workbox"),
            ("ssh://dev@workbox:2222/", "agents", "workbox/agents"),
        ] {
            assert_eq!(default_label(target, session), label, "{target} {session}");
        }
    }

    #[test]
    fn default_label_must_be_unique_and_fit() {
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("workbox", "workbox", "default").unwrap();

        assert!(check_default_label(&catalog, "workbox/agents").is_ok());
        let duplicate = check_default_label(&catalog, "workbox").unwrap_err();
        assert!(duplicate.contains("--label"), "{duplicate}");
        let long = check_default_label(&catalog, &"h".repeat(MAX_LABEL_BYTES + 1)).unwrap_err();
        assert!(long.contains("--label"), "{long}");
    }

    #[test]
    fn add_parser_rejects_incomplete_duplicate_and_extra_arguments() {
        for args in [
            vec![],
            vec!["--label", "coder"],
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
                &[id, "--local-session", "default", "--local-session=sandbox"],
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

    #[test]
    fn availability_parser_rejects_flag_first_while_clap_accepts() {
        let id = "0123456789abcdef0123456789abcdef";
        // Runtime is ID-first. Conventional Clap lets a required positional follow
        // flags, so help documents ID-first order without changing Clap grammar.
        let cases: &[&[&str]] = &[
            &["--all-local-sessions", id],
            &["--no-local-sessions", id],
            &["--local-session", "default", id],
            &["--local-session=default", id],
        ];
        for args in cases {
            let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(parse_availability_args(&owned).is_err(), "runtime {args:?}");
            let mut spec_args = vec![
                "herdr".to_string(),
                "machine".to_string(),
                "availability".to_string(),
            ];
            spec_args.extend(owned);
            assert!(
                crate::cli::spec_command()
                    .try_get_matches_from(spec_args)
                    .is_ok(),
                "spec {args:?}"
            );
        }
    }
}
