use super::*;

pub(super) fn should_watch_profiles(
    has_shell: bool,
    is_remote_client: bool,
    attach_escape: bool,
    local_session: Option<&str>,
) -> bool {
    has_shell && !is_remote_client && !attach_escape && local_session.is_some()
}

pub(super) fn watch_profiles(
    event_tx: tokio::sync::mpsc::Sender<ClientLoopEvent>,
    should_quit: Arc<AtomicBool>,
    local_session: String,
) {
    // One bounded read per second per client, independent of rendering and pane count.
    std::thread::spawn(move || {
        let mut previous = None;
        while !should_quit.load(Ordering::Acquire) {
            let current =
                endpoint::EndpointCatalog::load_profiles_for_local_session(&local_session);
            if previous.as_ref() != Some(&current) {
                previous = Some(current.clone());
                if event_tx
                    .blocking_send(ClientLoopEvent::EndpointCatalog(current))
                    .is_err()
                {
                    break;
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

#[derive(Default)]
pub(super) struct PendingCatalog {
    valid: Option<Vec<endpoint::SavedSshEndpoint>>,
    error: Option<String>,
}

impl PendingCatalog {
    pub(super) fn observe(&mut self, reload: Result<Vec<endpoint::SavedSshEndpoint>, String>) {
        match reload {
            Ok(profiles) => {
                self.valid = Some(profiles);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn has_valid(&self) -> bool {
        self.valid.is_some()
    }

    pub(super) fn take_valid(&mut self) -> Option<Vec<endpoint::SavedSshEndpoint>> {
        self.valid.take()
    }

    pub(super) fn take_error(&mut self) -> Option<String> {
        self.error.take()
    }
}

pub(super) fn spawn_due_if_ready(pending: &PendingCatalog, spawn: impl FnOnce()) {
    if !pending.has_valid() {
        spawn();
    }
}

// Only called between surface handoffs: removing a source must not invalidate an in-flight
// rollback. Connection attempts are independent and fenced by supervisor generations.
pub(super) fn apply_profiles(
    state: &mut ClientState,
    endpoints: &mut endpoint::EndpointRegistry,
    commands: &mut endpoint_commands::EndpointCommands,
    supervisors: &mut endpoint::EndpointSupervisors,
    catalog: &mut endpoint::EndpointCatalog,
    profiles: Vec<endpoint::SavedSshEndpoint>,
    now: std::time::Instant,
) -> bool {
    if catalog.ssh == profiles {
        return false;
    }
    let previous_size = state
        .shell
        .as_ref()
        .map(|shell| shell.surface_size(state.reported_size.0, state.reported_size.1));
    let retired = supervisors.reconcile_profiles(&profiles, now);
    let active_removed = retired.contains(endpoints.active_id());
    for endpoint_id in retired {
        endpoints.disconnect(&endpoint_id);
        let cancelled = commands.disconnect(&endpoint_id);
        #[cfg(unix)]
        state.retire_endpoint_graphics(&endpoint_id);
        if let Some(shell) = state.shell.as_mut() {
            for request_id in cancelled {
                shell.cancel_endpoint_request(&request_id);
            }
            shell.retire_endpoint(&endpoint_id);
        }
    }
    catalog.ssh = profiles;
    if active_removed {
        endpoints.select_unavailable_local();
        catalog.select_local();
        state.freeze_presentation();
        if let Some(shell) = state.shell.as_mut() {
            shell.select_unavailable_local();
        }
    } else if catalog.selected_profile.as_ref().is_some_and(|selected| {
        !catalog
            .ssh
            .iter()
            .any(|profile| &profile.id == selected && profile.enabled)
    }) {
        catalog.select_local();
    }
    if let Some(shell) = state.shell.as_mut() {
        shell.set_endpoint_catalog(&catalog.ssh);
        if endpoints.active_surface_available()
            && previous_size
                != Some(shell.surface_size(state.reported_size.0, state.reported_size.1))
        {
            shell.invalidate_pane_surface();
            endpoints.send(&client_shell_resize_message(
                shell,
                state.reported_size.0,
                state.reported_size.1,
                state.reported_cell_size.0,
                state.reported_cell_size.1,
                state.pixel_geometry_exact,
            ));
        }
    }
    active_removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use endpoint::{ClientEndpointId, EndpointCatalog, EndpointRegistry, EndpointSupervisors};
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    struct Transport(Arc<AtomicUsize>);

    impl endpoint::EndpointTransport for Transport {
        fn send(&mut self, _: &ClientMessage) -> io::Result<()> {
            Ok(())
        }

        fn disconnect(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn state() -> ClientState {
        ClientState {
            blit_encoder: render_ansi::BlitEncoder::new(),
            mouse_capture_active: false,
            endpoint_mouse_capture_requested: false,
            endpoint_sgr_pixels_requested: false,
            host_theme_updates: Vec::new(),
            direct_mouse_capture_preference: false,
            shell_mouse_capture_preference: false,
            direct_keyboard_protocol: Default::default(),
            pane_keyboard_report_all: false,
            keyboard_report_all_active: false,
            reported_size: (100, 30),
            reported_cell_size: (0, 0),
            sound_config: Default::default(),
            kitty_graphics_enabled: false,
            pixel_geometry_enabled: false,
            pixel_geometry_exact: false,
            #[cfg(unix)]
            direct_graphics_response: Default::default(),
            #[cfg(unix)]
            retired_direct_graphics: None,
            #[cfg(unix)]
            pending_surface_graphics: HashMap::new(),
            attach_escape: None,
            #[cfg(unix)]
            mouse_scroll_lines: 3,
            remote_image_paste_key: None,
            redraw_on_focus_gained: false,
            repaint_pending: false,
            presentation_frozen: false,
            draw_host_cursor: false,
            detached_process_children: Vec::new(),
            shell: Some(shell::ClientShellState::new(
                shell::ClientShellConfig::from_config(&crate::config::Config::default()),
            )),
        }
    }

    #[test]
    fn live_catalog_add_and_rename_keep_local_connection_and_selection() {
        let now = Instant::now();
        let mut state = state();
        let disconnected = Arc::new(AtomicUsize::new(0));
        let mut endpoints =
            EndpointRegistry::new(Transport(disconnected.clone()), 1, Default::default());
        let mut supervisors = EndpointSupervisors::new(&[], now);
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut catalog = EndpointCatalog::default();
        let mut profile = endpoint::SavedSshEndpoint::new("Build", "build", "main").unwrap();
        for label in ["Build", "Renamed"] {
            profile.label = label.into();
            assert!(!apply_profiles(
                &mut state,
                &mut endpoints,
                &mut commands,
                &mut supervisors,
                &mut catalog,
                vec![profile.clone()],
                now
            ));
            assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
            assert!(endpoints.active_surface_available());
            assert_eq!(
                endpoints
                    .connection(&ClientEndpointId::Local)
                    .unwrap()
                    .generation,
                1
            );
            assert_eq!(catalog.selected_profile, None);
            assert_eq!(
                state
                    .shell
                    .as_ref()
                    .unwrap()
                    .endpoint_label(&ClientEndpointId::Ssh(profile.id.clone())),
                label
            );
        }
        assert_eq!(disconnected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn live_catalog_remove_or_disable_active_machine_selects_local_without_input() {
        for local_online in [false, true] {
            for disable in [false, true] {
                let now = Instant::now();
                let mut state = state();
                let mut catalog = EndpointCatalog::default();
                let id = catalog.add_ssh("Build", "build", "main").unwrap();
                let remote = ClientEndpointId::Ssh(id.clone());
                catalog.select_ssh(&id);
                state
                    .shell
                    .as_mut()
                    .unwrap()
                    .set_endpoint_catalog(&catalog.ssh);
                let mut supervisors = EndpointSupervisors::new(&catalog.ssh, now);
                let mut endpoints = EndpointRegistry::empty();
                let local_disconnects = Arc::new(AtomicUsize::new(0));
                if local_online {
                    endpoints.insert(
                        ClientEndpointId::Local,
                        Transport(local_disconnects.clone()),
                        1,
                        Default::default(),
                        false,
                    );
                }
                let remote_disconnects = Arc::new(AtomicUsize::new(0));
                endpoints.insert(
                    remote.clone(),
                    Transport(remote_disconnects.clone()),
                    2,
                    Default::default(),
                    true,
                );
                endpoints.set_active(&remote);
                endpoints.unfreeze_input();
                let mut commands = endpoint_commands::EndpointCommands::default();
                let profiles = if disable {
                    let mut profiles = catalog.ssh.clone();
                    profiles[0].enabled = false;
                    profiles
                } else {
                    Vec::new()
                };
                assert!(apply_profiles(
                    &mut state,
                    &mut endpoints,
                    &mut commands,
                    &mut supervisors,
                    &mut catalog,
                    profiles,
                    now
                ));
                assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
                assert!(!endpoints.active_surface_available());
                assert!(endpoints.connection(&remote).is_none());
                assert_eq!(
                    endpoints.connection(&ClientEndpointId::Local).is_some(),
                    local_online
                );
                assert!(state
                    .shell
                    .as_ref()
                    .unwrap()
                    .endpoint_is_active(&ClientEndpointId::Local));
                assert!(!state.shell.as_ref().unwrap().has_presented_surface());
                assert!(state.presentation_frozen);
                assert_eq!(catalog.selected_profile, None);
                assert_eq!(remote_disconnects.load(Ordering::Relaxed), 1);
                assert_eq!(local_disconnects.load(Ordering::Relaxed), 0);
                assert!(!supervisors.record_status(
                    &remote,
                    2,
                    endpoint::ClientEndpointStatus::Online,
                    now
                ));
            }
        }
    }

    #[test]
    fn should_watch_profiles_requires_valid_local_context() {
        assert!(should_watch_profiles(true, false, false, Some("default")));
        assert!(!should_watch_profiles(true, false, false, None));
        assert!(!should_watch_profiles(true, true, false, Some("default")));
        assert!(!should_watch_profiles(false, false, false, Some("default")));
        assert!(!should_watch_profiles(true, false, true, Some("default")));
    }

    #[test]
    fn pending_catalog_interleavings_preserve_latest_valid_observation() {
        let first = endpoint::SavedSshEndpoint::new("One", "one", "main").unwrap();
        let second = endpoint::SavedSshEndpoint::new("Two", "two", "main").unwrap();
        let mut pending = PendingCatalog::default();
        pending.observe(Ok(vec![first.clone()]));
        pending.observe(Ok(vec![second.clone()]));
        pending.observe(Err("malformed".into()));
        assert_eq!(pending.take_valid(), Some(vec![second.clone()]));
        assert_eq!(pending.take_error(), Some("malformed".into()));

        pending.observe(Err("first-error".into()));
        assert!(pending.take_valid().is_none());
        assert_eq!(pending.take_error(), Some("first-error".into()));

        pending.observe(Err("stale".into()));
        pending.observe(Ok(vec![first.clone()]));
        assert!(pending.take_error().is_none());
        assert_eq!(pending.take_valid(), Some(vec![first]));
    }

    #[test]
    fn pending_valid_catalog_pauses_new_connection_attempts() {
        let mut pending = PendingCatalog::default();
        let spawn_count = std::cell::Cell::new(0);
        let spawn = || spawn_count.set(spawn_count.get() + 1);
        pending.observe(Ok(vec![endpoint::SavedSshEndpoint::new(
            "One", "one", "main",
        )
        .unwrap()]));
        spawn_due_if_ready(&pending, spawn);
        pending.observe(Err("later".into()));
        spawn_due_if_ready(&pending, spawn);
        assert_eq!(spawn_count.get(), 0);
        let _ = pending.take_valid();
        spawn_due_if_ready(&pending, spawn);
        assert_eq!(spawn_count.get(), 1);
    }

    fn workspace_list(id: &str) -> Box<crate::api::schema::Request> {
        Box::new(crate::api::schema::Request {
            id: id.into(),
            method: crate::api::schema::Method::WorkspaceList(crate::api::schema::EmptyParams {}),
        })
    }

    #[test]
    fn live_allowlist_change_retires_active_and_background_endpoints() {
        let now = Instant::now();
        let mut catalog = EndpointCatalog::default();
        let victim = catalog.add_ssh("Active", "active", "main").unwrap();
        let survivor = catalog.add_ssh("Survivor", "survivor", "main").unwrap();
        let background = catalog.add_ssh("Background", "background", "main").unwrap();
        let victim_id = ClientEndpointId::Ssh(victim.clone());
        let survivor_id = ClientEndpointId::Ssh(survivor.clone());
        let background_id = ClientEndpointId::Ssh(background.clone());
        catalog.select_ssh(&victim);

        let mut state = state();
        state.shell = Some(shell::ClientShellState::test_with_projected_profiles(
            &catalog.ssh,
            &victim_id,
        ));
        let shell = state.shell.as_mut().unwrap();
        shell.test_seed_pending_request("req-victim", "active-boot");
        shell.test_seed_notification(victim_id.clone(), "victim-notice");
        shell.test_seed_notification(survivor_id.clone(), "survivor-notice");
        shell.test_seed_notification(background_id.clone(), "background-notice");
        assert!(shell.endpoint_is_active(&victim_id));
        assert!(shell.test_composed_contains("active-workspace"));
        assert!(shell.test_has_pending_request("req-victim"));
        assert!(shell.test_has_notification_for(&victim_id));
        assert!(shell.test_has_notification_for(&survivor_id));
        assert!(shell.test_has_notification_for(&background_id));

        let mut supervisors = EndpointSupervisors::new(&catalog.ssh, now);
        let mut endpoints = EndpointRegistry::empty();
        let victim_drops = Arc::new(AtomicUsize::new(0));
        let survivor_drops = Arc::new(AtomicUsize::new(0));
        let background_drops = Arc::new(AtomicUsize::new(0));
        endpoints.insert(
            victim_id.clone(),
            Transport(victim_drops.clone()),
            2,
            Default::default(),
            true,
        );
        endpoints.insert(
            survivor_id.clone(),
            Transport(survivor_drops.clone()),
            3,
            Default::default(),
            true,
        );
        endpoints.insert(
            background_id.clone(),
            Transport(background_drops.clone()),
            4,
            Default::default(),
            false,
        );
        endpoints.set_active(&victim_id);
        let mut commands = endpoint_commands::EndpointCommands::default();
        commands.enqueue(
            victim_id.clone(),
            2,
            "active-boot".into(),
            workspace_list("req-victim"),
        );
        commands.enqueue(
            survivor_id.clone(),
            3,
            "survivor-boot".into(),
            workspace_list("req-survivor"),
        );
        assert_eq!(commands.queued_count(&victim_id), 1);
        assert_eq!(commands.queued_count(&survivor_id), 1);

        let after_victim = catalog
            .ssh
            .iter()
            .filter(|profile| profile.id != victim)
            .cloned()
            .collect::<Vec<_>>();
        assert!(apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            after_victim.clone(),
            now
        ));
        assert_eq!(endpoints.active_id(), &ClientEndpointId::Local);
        assert!(endpoints.connection(&victim_id).is_none());
        assert!(endpoints.connection(&survivor_id).is_some());
        assert!(endpoints.connection(&background_id).is_some());
        assert_eq!(catalog.selected_profile, None);
        assert_eq!(victim_drops.load(Ordering::Relaxed), 1);
        assert_eq!(survivor_drops.load(Ordering::Relaxed), 0);
        assert_eq!(background_drops.load(Ordering::Relaxed), 0);
        assert_eq!(commands.queued_count(&victim_id), 0);
        assert_eq!(commands.queued_count(&survivor_id), 1);
        {
            let shell = state.shell.as_mut().unwrap();
            assert!(shell.endpoint_is_active(&ClientEndpointId::Local));
            assert!(shell.endpoint_status(&victim_id).is_none());
            assert!(!shell.test_has_pending_request("req-victim"));
            assert!(!shell.test_has_notification_for(&victim_id));
            assert!(shell.test_has_notification_for(&survivor_id));
            assert!(shell.test_has_notification_for(&background_id));
            assert!(!shell.test_composed_contains("active-workspace"));
        }
        assert!(!supervisors.record_status(
            &victim_id,
            2,
            endpoint::ClientEndpointStatus::Online,
            now
        ));

        assert!(endpoints.set_active(&survivor_id));
        catalog.select_ssh(&survivor);
        {
            let shell = state.shell.as_mut().unwrap();
            assert!(shell.activate_endpoint_projection(&survivor_id));
            shell.test_install_projected_surface("survivor-boot");
            shell.test_seed_pending_request("req-background", "background-boot");
        }
        commands.enqueue(
            background_id.clone(),
            4,
            "background-boot".into(),
            workspace_list("req-background"),
        );
        assert_eq!(commands.queued_count(&survivor_id), 1);
        assert_eq!(commands.queued_count(&background_id), 1);

        let only_survivor = after_victim
            .into_iter()
            .filter(|profile| profile.id == survivor)
            .collect::<Vec<_>>();
        assert!(!apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            only_survivor,
            now
        ));
        assert_eq!(endpoints.active_id(), &survivor_id);
        assert!(endpoints.connection(&survivor_id).is_some());
        assert!(endpoints.connection(&background_id).is_none());
        assert_eq!(survivor_drops.load(Ordering::Relaxed), 0);
        assert_eq!(background_drops.load(Ordering::Relaxed), 1);
        assert_eq!(commands.queued_count(&survivor_id), 1);
        assert_eq!(commands.queued_count(&background_id), 0);
        {
            let shell = state.shell.as_mut().unwrap();
            assert!(shell.endpoint_is_active(&survivor_id));
            assert!(shell.endpoint_status(&background_id).is_none());
            assert!(!shell.test_has_pending_request("req-background"));
            assert!(!shell.test_has_notification_for(&background_id));
            assert!(shell.test_has_notification_for(&survivor_id));
            assert!(shell.test_composed_contains("survivor-workspace"));
        }
    }

    #[test]
    fn malformed_live_catalog_keeps_connections_then_recovers() {
        let now = Instant::now();
        let mut state = state();
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "main").unwrap();
        let remote = ClientEndpointId::Ssh(id);
        state
            .shell
            .as_mut()
            .unwrap()
            .set_endpoint_catalog(&catalog.ssh);
        let mut supervisors = EndpointSupervisors::new(&catalog.ssh, now);
        let remote_drops = Arc::new(AtomicUsize::new(0));
        let mut endpoints = EndpointRegistry::empty();
        endpoints.insert(
            ClientEndpointId::Local,
            Transport(Arc::new(AtomicUsize::new(0))),
            1,
            Default::default(),
            true,
        );
        endpoints.insert(
            remote.clone(),
            Transport(remote_drops.clone()),
            2,
            Default::default(),
            false,
        );
        let mut commands = endpoint_commands::EndpointCommands::default();
        let applied = catalog.ssh.clone();
        let mut pending = PendingCatalog::default();
        pending.observe(Err("malformed".into()));
        assert!(pending.take_valid().is_none());
        assert!(!apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            applied.clone(),
            now
        ));
        assert!(endpoints.connection(&remote).is_some());
        assert_eq!(remote_drops.load(Ordering::Relaxed), 0);
        pending.observe(Ok(Vec::new()));
        pending.observe(Err("later".into()));
        let empty = pending.take_valid().unwrap();
        assert!(!apply_profiles(
            &mut state,
            &mut endpoints,
            &mut commands,
            &mut supervisors,
            &mut catalog,
            empty,
            now
        ));
        assert!(endpoints.connection(&remote).is_none());
        assert_eq!(remote_drops.load(Ordering::Relaxed), 1);
        assert_eq!(pending.take_error().as_deref(), Some("later"));
    }

    #[test]
    fn effective_startup_excludes_disallowed_supervisors_and_rows() {
        let now = Instant::now();
        let mut allowed = endpoint::SavedSshEndpoint::new("Allowed", "one", "main").unwrap();
        allowed.local_sessions = Some(vec!["default".into()]);
        let mut disallowed = endpoint::SavedSshEndpoint::new("Hidden", "two", "main").unwrap();
        disallowed.local_sessions = Some(vec!["tradingdroid".into()]);
        let mut disabled = endpoint::SavedSshEndpoint::new("Idle", "three", "main").unwrap();
        disabled.enabled = false;
        let mut catalog = EndpointCatalog::default();
        catalog.ssh = vec![allowed.clone(), disallowed.clone(), disabled.clone()];
        let default = catalog.profiles_for_local_session("default");
        let named = catalog.profiles_for_local_session("tradingdroid");
        let default_supervisors = EndpointSupervisors::new(&default, now);
        let named_supervisors = EndpointSupervisors::new(&named, now);
        assert!(default_supervisors.contains_ssh(&ClientEndpointId::Ssh(allowed.id.clone())));
        assert!(!default_supervisors.contains_ssh(&ClientEndpointId::Ssh(disallowed.id.clone())));
        assert!(!default_supervisors.contains_ssh(&ClientEndpointId::Ssh(disabled.id.clone())));
        assert!(!named_supervisors.contains_ssh(&ClientEndpointId::Ssh(allowed.id.clone())));
        assert!(named_supervisors.contains_ssh(&ClientEndpointId::Ssh(disallowed.id.clone())));
        let mut shell = shell::ClientShellState::new(shell::ClientShellConfig::from_config(
            &crate::config::Config::default(),
        ));
        shell.set_endpoint_catalog(&default);
        assert!(shell
            .endpoint_status(&ClientEndpointId::Ssh(disabled.id.clone()))
            .is_some());
        assert!(shell
            .endpoint_status(&ClientEndpointId::Ssh(disallowed.id))
            .is_none());
    }

    #[test]
    fn eligible_profile_edits_preserve_destination_semantics() {
        let now = Instant::now();
        let mut profile = endpoint::SavedSshEndpoint::new("Build", "build", "main").unwrap();
        profile.local_sessions = Some(vec!["default".into()]);
        let id = ClientEndpointId::Ssh(profile.id.clone());
        let mut supervisors = EndpointSupervisors::new(&[profile.clone()], now);
        supervisors.set_ssh_generation(&id, 4);
        profile.label = "Renamed".into();
        profile.local_sessions = Some(vec!["default".into(), "tradingdroid".into()]);
        assert!(supervisors
            .reconcile_profiles(&[profile.clone()], now)
            .is_empty());
        assert_eq!(supervisors.ssh_generation(&id), Some(4));
        profile.session = "other".into();
        assert_eq!(
            supervisors.reconcile_profiles(&[profile.clone()], now),
            vec![id.clone()]
        );
        profile.local_sessions = Some(vec!["tradingdroid".into()]);
        let mut filtered_catalog = EndpointCatalog::default();
        filtered_catalog.ssh = vec![profile];
        let filtered = filtered_catalog.profiles_for_local_session("default");
        assert!(filtered.is_empty());
        assert_eq!(
            supervisors.reconcile_profiles(&filtered, now),
            vec![id.clone()]
        );
        assert!(!supervisors.contains_ssh(&id));
    }
}
