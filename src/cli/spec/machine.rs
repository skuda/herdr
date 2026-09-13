use clap::{Arg, ArgGroup, Command};

use super::{flag, json_flag, option, repeatable_option};

pub(super) fn command() -> Command {
    Command::new("machine")
        .about("Manage saved SSH machines")
        .subcommand(
            Command::new("list")
                .about("List saved SSH machines")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("add")
                .about("Prepare the remote Herdr server and save an SSH machine")
                .arg(
                    Arg::new("ssh-target")
                        .value_name("SSH_TARGET")
                        .required(true),
                )
                .arg(
                    option("label", "LABEL")
                        .required(true)
                        .help("Set the machine label shown in the sidebar"),
                )
                .arg(
                    option("remote-session", "NAME")
                        .help("Set the explicit Herdr session on the remote machine"),
                ),
        )
        .subcommand(
            profile_command("rename", "Rename a saved SSH machine").arg(
                option("label", "LABEL")
                    .required(true)
                    .help("Set the machine label shown in the sidebar"),
            ),
        )
        .subcommand(profile_command("remove", "Remove a saved SSH machine"))
        .subcommand(profile_command("enable", "Enable a saved SSH machine"))
        .subcommand(profile_command("disable", "Disable a saved SSH machine"))
        .subcommand(
            profile_command(
                "availability",
                "Limit a saved SSH machine to specific local sessions",
            )
            .mut_arg("profile-id", |arg| {
                arg.value_parser(|id: &str| {
                    crate::client::endpoint::ProfileId::parse(id).map(|id| id.to_string())
                })
            })
            .arg(
                repeatable_option("local-session", "NAME")
                    .value_parser(|name: &str| {
                        crate::session::validate_name(name).map(|()| name.to_string())
                    })
                    .help("Allow this machine only in these local sessions"),
            )
            .arg(flag("all-local-sessions").help("Allow this machine in every local session"))
            .arg(flag("no-local-sessions").help("Allow this machine in no local session"))
            .group(
                ArgGroup::new("availability")
                    .args(["local-session", "all-local-sessions", "no-local-sessions"])
                    .required(true),
            ),
        )
}

fn profile_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about).arg(
        Arg::new("profile-id")
            .value_name("PROFILE_ID")
            .required(true),
    )
}
