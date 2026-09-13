use std::collections::HashSet;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::ProfileId;

const CATALOG_VERSION: u32 = 1;
const SELECTION_VERSION: u32 = 1;
const MAX_CATALOG_BYTES: u64 = 64 * 1024;
const MAX_PROFILES: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 1024;
const MAX_LOCAL_SESSIONS: usize = 64;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSshEndpoint {
    pub(crate) id: ProfileId,
    pub(crate) label: String,
    pub(crate) target: String,
    pub(crate) session: String,
    pub(crate) enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_sessions: Option<Vec<String>>,
}

impl SavedSshEndpoint {
    pub(crate) fn new(
        label: impl Into<String>,
        target: impl Into<String>,
        session: impl Into<String>,
    ) -> Result<Self, String> {
        let profile = Self {
            id: ProfileId::generate(),
            label: label.into(),
            target: target.into(),
            session: session.into(),
            enabled: true,
            local_sessions: None,
        };
        profile.validate()?;
        Ok(profile)
    }

    // Temporary S1 staging: production callers land in S4/S5.
    #[cfg(test)]
    pub(crate) fn locally_allowed_in(&self, local_session: &str) -> bool {
        match &self.local_sessions {
            None => true,
            Some(sessions) => sessions.iter().any(|name| name == local_session),
        }
    }

    // Temporary S1 staging: production callers land in S4/S5.
    #[cfg(test)]
    pub(crate) fn is_available_in(&self, local_session: &str) -> bool {
        self.enabled && self.locally_allowed_in(local_session)
    }

    fn validate(&self) -> Result<(), String> {
        ProfileId::parse(self.id.to_string())?;
        let label = self.label.trim();
        if label.is_empty() {
            return Err("SSH endpoint label cannot be empty".into());
        }
        if label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
            return Err(format!(
                "SSH endpoint label must be at most {MAX_LABEL_BYTES} bytes and contain no control characters"
            ));
        }
        if self.target.len() > MAX_TARGET_BYTES || self.target.chars().any(char::is_control) {
            return Err(format!(
                "SSH target must be at most {MAX_TARGET_BYTES} bytes and contain no control characters"
            ));
        }
        crate::remote::validate_remote_target(&self.target).map(|_| ())?;
        let authority = self.target.strip_prefix("ssh://").unwrap_or(&self.target);
        if authority
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
        {
            return Err("SSH target must not contain a password".into());
        }
        crate::session::validate_name(&self.session)?;
        normalize_local_sessions(self.local_sessions.as_deref())?;
        Ok(())
    }
}

pub(crate) fn normalize_local_sessions(
    sessions: Option<&[String]>,
) -> Result<Option<Vec<String>>, String> {
    let Some(sessions) = sessions else {
        return Ok(None);
    };
    if sessions.len() > MAX_LOCAL_SESSIONS {
        return Err(format!(
            "SSH endpoint cannot list more than {MAX_LOCAL_SESSIONS} local sessions"
        ));
    }
    for name in sessions {
        crate::session::validate_name(name)?;
    }
    let mut normalized = sessions.to_vec();
    normalized.sort();
    normalized.dedup();
    Ok(Some(normalized))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointCatalog {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_profile: Option<ProfileId>,
    #[serde(default)]
    pub(crate) ssh: Vec<SavedSshEndpoint>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSelection {
    version: u32,
    selected_profile: Option<ProfileId>,
}

impl Default for EndpointCatalog {
    fn default() -> Self {
        Self {
            version: CATALOG_VERSION,
            selected_profile: None,
            ssh: Vec::new(),
        }
    }
}

impl EndpointCatalog {
    pub(crate) fn load() -> Result<Self, String> {
        Self::load_from_paths(&catalog_path(), &selection_path())
    }

    pub(crate) fn load_profiles() -> Result<Vec<SavedSshEndpoint>, String> {
        // Live clients keep their own selection, independent of other attached clients.
        Self::load_from_path(&catalog_path()).map(|catalog| catalog.ssh)
    }

    fn load_from_paths(catalog_path: &Path, selection_path: &Path) -> Result<Self, String> {
        let mut catalog = Self::load_from_path(catalog_path)?;
        match load_selection_from_path(selection_path) {
            Ok(Some(selection)) => {
                let valid = selection.selected_profile.as_ref().is_none_or(|selected| {
                    catalog
                        .ssh
                        .iter()
                        .any(|profile| &profile.id == selected && profile.enabled)
                });
                if valid {
                    catalog.selected_profile = selection.selected_profile;
                } else {
                    tracing::warn!(
                        path = %selection_path.display(),
                        "saved endpoint selection is absent or disabled; using Local"
                    );
                    catalog.selected_profile = None;
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %selection_path.display(),
                    "saved endpoint selection is unavailable; using Local"
                );
                catalog.selected_profile = None;
            }
        }
        if !catalog.embedded_selection_is_globally_valid() {
            catalog.selected_profile = None;
        }
        Ok(catalog)
    }

    pub(crate) fn store_profiles(&self) -> Result<(), String> {
        self.store_to_path(&catalog_path())
    }

    pub(crate) fn store_selection(&self) -> Result<(), String> {
        self.store_selection_to_path(&selection_path())
    }

    fn store_selection_to_path(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let content = serde_json::to_vec_pretty(&EndpointSelection {
            version: SELECTION_VERSION,
            selected_profile: self.selected_profile.clone(),
        })
        .map_err(|error| format!("failed to encode endpoint selection: {error}"))?;
        store_private_json(path, &content, "endpoint selection")
    }

    pub(crate) fn add_ssh(
        &mut self,
        label: impl Into<String>,
        target: impl Into<String>,
        session: impl Into<String>,
    ) -> Result<ProfileId, String> {
        if self.ssh.len() >= MAX_PROFILES {
            return Err(format!("at most {MAX_PROFILES} SSH endpoints can be saved"));
        }
        let profile = SavedSshEndpoint::new(label, target, session)?;
        let id = profile.id.clone();
        self.ssh.push(profile);
        Ok(id)
    }

    pub(crate) fn rename_ssh(
        &mut self,
        id: &ProfileId,
        label: impl Into<String>,
    ) -> Result<bool, String> {
        let Some(index) = self.ssh.iter().position(|profile| &profile.id == id) else {
            return Ok(false);
        };
        let mut renamed = self.ssh[index].clone();
        renamed.label = label.into();
        renamed.validate()?;
        self.ssh[index] = renamed;
        Ok(true)
    }

    pub(crate) fn remove_ssh(&mut self, id: &ProfileId) -> bool {
        let previous_len = self.ssh.len();
        self.ssh.retain(|profile| &profile.id != id);
        if self.selected_profile.as_ref() == Some(id) {
            self.selected_profile = None;
        }
        self.ssh.len() != previous_len
    }

    pub(crate) fn select_local(&mut self) {
        self.selected_profile = None;
    }

    pub(crate) fn select_endpoint(&mut self, endpoint_id: &super::ClientEndpointId) -> bool {
        match endpoint_id {
            super::ClientEndpointId::Local => {
                self.select_local();
                true
            }
            super::ClientEndpointId::Ssh(profile_id) => self.select_ssh(profile_id),
        }
    }

    pub(crate) fn select_ssh(&mut self, id: &ProfileId) -> bool {
        if !self
            .ssh
            .iter()
            .any(|profile| &profile.id == id && profile.enabled)
        {
            return false;
        }
        self.selected_profile = Some(id.clone());
        true
    }

    pub(crate) fn has_enabled_ssh(&self) -> bool {
        self.ssh.iter().any(|profile| profile.enabled)
    }

    pub(crate) fn contains_enabled_target_session(&self, target: &str, session: &str) -> bool {
        self.ssh.iter().any(|profile| {
            profile.enabled && profile.target == target && profile.session == session
        })
    }

    pub(crate) fn set_enabled(&mut self, id: &ProfileId, enabled: bool) -> bool {
        let Some(profile) = self.ssh.iter_mut().find(|profile| &profile.id == id) else {
            return false;
        };
        profile.enabled = enabled;
        if !enabled && self.selected_profile.as_ref() == Some(id) {
            self.selected_profile = None;
        }
        true
    }

    fn validate(&self) -> Result<(), String> {
        self.validate_profiles()?;
        if !self.embedded_selection_is_globally_valid() {
            return Err("selected SSH endpoint is absent or disabled in the catalog".into());
        }
        Ok(())
    }

    fn validate_profiles(&self) -> Result<(), String> {
        if self.version != CATALOG_VERSION {
            return Err(format!(
                "unsupported endpoint catalog version {}; expected {CATALOG_VERSION}",
                self.version
            ));
        }
        if self.ssh.len() > MAX_PROFILES {
            return Err(format!(
                "endpoint catalog contains more than {MAX_PROFILES} SSH profiles"
            ));
        }
        let mut ids = HashSet::new();
        for profile in &self.ssh {
            profile.validate()?;
            if !ids.insert(profile.id.clone()) {
                return Err(format!("duplicate endpoint profile id {}", profile.id));
            }
        }
        Ok(())
    }

    fn embedded_selection_is_globally_valid(&self) -> bool {
        self.selected_profile.as_ref().is_none_or(|selected| {
            ProfileId::parse(selected.as_str()).is_ok()
                && self
                    .ssh
                    .iter()
                    .any(|profile| &profile.id == selected && profile.enabled)
        })
    }

    // Temporary S1 staging: production callers land in S3.
    #[cfg(test)]
    fn resolved_embedded_selection(&self, local_session: &str) -> Option<&ProfileId> {
        let selected = self.selected_profile.as_ref()?;
        if ProfileId::parse(selected.as_str()).is_err() {
            return None;
        }
        self.ssh
            .iter()
            .any(|profile| &profile.id == selected && profile.is_available_in(local_session))
            .then_some(selected)
    }

    fn normalize_embedded_selection(&mut self) {
        if !self.embedded_selection_is_globally_valid() {
            self.selected_profile = None;
        }
    }

    fn normalize_local_session_lists(&mut self) -> Result<(), String> {
        for profile in &mut self.ssh {
            profile.local_sessions = normalize_local_sessions(profile.local_sessions.as_deref())?;
        }
        Ok(())
    }

    fn load_from_path(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(format!(
                    "failed to open endpoint catalog {}: {error}",
                    path.display()
                ))
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect endpoint catalog: {error}"))?;
        if metadata.len() > MAX_CATALOG_BYTES {
            return Err("endpoint catalog exceeds the storage limit".into());
        }
        let mut content = String::new();
        file.take(MAX_CATALOG_BYTES + 1)
            .read_to_string(&mut content)
            .map_err(|error| format!("failed to read endpoint catalog: {error}"))?;
        if content.len() as u64 > MAX_CATALOG_BYTES {
            return Err("endpoint catalog exceeds the storage limit".into());
        }
        let mut catalog: Self = serde_json::from_str(&content)
            .map_err(|error| format!("stored endpoint catalog is invalid: {error}"))?;
        catalog.validate_profiles()?;
        catalog.normalize_local_session_lists()?;
        Ok(catalog)
    }

    fn store_to_path(&self, path: &Path) -> Result<(), String> {
        let mut catalog = self.clone();
        catalog.normalize_local_session_lists()?;
        catalog.normalize_embedded_selection();
        catalog.validate()?;
        let content = serde_json::to_vec_pretty(&catalog)
            .map_err(|error| format!("failed to encode endpoint catalog: {error}"))?;
        store_private_json(path, &content, "endpoint catalog")
    }
}

fn load_selection_from_path(path: &Path) -> Result<Option<EndpointSelection>, String> {
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read endpoint selection: {error}")),
    };
    if content.len() as u64 > MAX_CATALOG_BYTES {
        return Err("endpoint selection exceeds the storage limit".into());
    }
    let selection: EndpointSelection = serde_json::from_slice(&content)
        .map_err(|error| format!("stored endpoint selection is invalid: {error}"))?;
    if selection.version != SELECTION_VERSION {
        return Err(format!(
            "unsupported endpoint selection version {}; expected {SELECTION_VERSION}",
            selection.version
        ));
    }
    Ok(Some(selection))
}

fn store_private_json(path: &Path, content: &[u8], description: &str) -> Result<(), String> {
    if content.len() as u64 > MAX_CATALOG_BYTES {
        return Err(format!("{description} exceeds the storage limit"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid {description} path: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {description} directory: {error}"))?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "refusing to replace {description} through a non-file path"
            ));
        }
    }

    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(".endpoints-{}-{sequence}.tmp", std::process::id()));
    let mut temp = crate::platform::create_private_state_file(&temp_path)
        .map_err(|error| format!("failed to create {description}: {error}"))?;
    if let Err(error) = temp.write_all(content).and_then(|()| temp.sync_all()) {
        drop(temp);
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to write {description}: {error}"));
    }
    drop(temp);
    if let Err(error) = crate::platform::replace_file(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("failed to activate {description}: {error}"));
    }
    crate::platform::sync_parent_directory(parent)
        .map_err(|error| format!("failed to persist {description} directory: {error}"))
}

pub(crate) fn catalog_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("endpoints.json")
}

fn selection_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("endpoint-selection.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "herdr-endpoint-catalog-{}-{name}",
                std::process::id()
            ))
            .join("endpoints.json")
    }

    #[test]
    fn catalog_roundtrip_persists_profiles_without_secret_fields() {
        let path = path("roundtrip");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog
            .add_ssh("Build", "ssh://dev@build.example:2222", "agents")
            .unwrap();
        assert!(catalog.select_ssh(&id));
        catalog.store_to_path(&path).unwrap();

        let encoded = std::fs::read_to_string(&path).unwrap();
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("control_socket"));
        assert!(!encoded.contains("local_sessions"));
        let loaded = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(loaded, catalog);
        assert_eq!(loaded.ssh[0].id, id);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn duplicate_target_and_session_profiles_keep_distinct_opaque_ids() {
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "build", "default").unwrap();
        let second = catalog.add_ssh("Two", "build", "default").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn catalog_rejects_passwords_embedded_in_ssh_targets() {
        let mut catalog = EndpointCatalog::default();
        assert!(catalog
            .add_ssh("Build", "ssh://dev:secret@build.example", "default")
            .unwrap_err()
            .contains("must not contain a password"));
        assert!(catalog
            .add_ssh("Build", "dev:secret@build.example", "default")
            .is_err());
        assert!(catalog
            .add_ssh("Build", "ssh://dev@[::1]:2222", "default")
            .is_ok());
    }

    #[test]
    fn interactive_bootstrap_matches_only_enabled_target_and_session() {
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        assert!(catalog.contains_enabled_target_session("build", "agents"));
        assert!(!catalog.contains_enabled_target_session("build", "default"));
        assert!(catalog.set_enabled(&id, false));
        assert!(!catalog.contains_enabled_target_session("build", "agents"));
    }

    #[test]
    fn rename_changes_only_the_machine_label() {
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Old", "build", "agents").unwrap();
        let original = catalog.ssh[0].clone();

        assert!(catalog.rename_ssh(&id, "New").unwrap());
        assert_eq!(catalog.ssh[0].label, "New");
        assert_eq!(catalog.ssh[0].id, original.id);
        assert_eq!(catalog.ssh[0].target, original.target);
        assert_eq!(catalog.ssh[0].session, original.session);
        assert!(catalog.rename_ssh(&id, "\n").is_err());
        assert_eq!(catalog.ssh[0].label, "New");
    }

    #[test]
    fn removal_and_disable_return_selection_to_local() {
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "one", "default").unwrap();
        assert!(catalog.select_ssh(&first));
        assert!(catalog.set_enabled(&first, false));
        assert_eq!(catalog.selected_profile, None);

        assert!(catalog.set_enabled(&first, true));
        assert!(catalog.select_ssh(&first));
        assert!(catalog.remove_ssh(&first));
        assert_eq!(catalog.selected_profile, None);
    }

    #[test]
    fn catalog_rejects_unknown_fields_instead_of_retaining_possible_secrets() {
        let path = path("unknown-field");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{
              "version": 1,
              "ssh": [{
                "id": "0123456789abcdef0123456789abcdef",
                "label": "Build",
                "target": "build",
                "session": "default",
                "enabled": true,
                "password": "must-not-be-accepted"
              }]
            }"#,
        )
        .unwrap();
        assert!(EndpointCatalog::load_from_path(&path)
            .unwrap_err()
            .contains("unknown field"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn storing_selection_does_not_rewrite_profile_membership() {
        let catalog_path = path("separate-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let profiles_before = std::fs::read(&catalog_path).unwrap();

        assert!(catalog.select_ssh(&id));
        catalog.store_selection_to_path(&selection_path).unwrap();

        assert_eq!(std::fs::read(&catalog_path).unwrap(), profiles_before);
        assert_eq!(
            load_selection_from_path(&selection_path)
                .unwrap()
                .unwrap()
                .selected_profile,
            Some(id)
        );
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn malformed_selection_does_not_discard_saved_profiles() {
        let catalog_path = path("malformed-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        assert!(catalog.select_ssh(&id));
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(&selection_path, b"not json").unwrap();

        let loaded = EndpointCatalog::load_from_paths(&catalog_path, &selection_path).unwrap();
        assert_eq!(loaded.ssh.len(), 1);
        assert_eq!(loaded.ssh[0].id, id);
        assert_eq!(loaded.selected_profile, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn absent_selected_profile_falls_back_without_discarding_catalog() {
        let catalog_path = path("absent-selection");
        let selection_path = catalog_path.with_file_name("selection.json");
        let _ = std::fs::remove_dir_all(catalog_path.parent().unwrap());
        let mut catalog = EndpointCatalog::default();
        let saved = catalog.add_ssh("Build", "build", "agents").unwrap();
        assert!(catalog.select_ssh(&saved));
        catalog.store_to_path(&catalog_path).unwrap();
        let missing = ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap();
        store_private_json(
            &selection_path,
            &serde_json::to_vec(&EndpointSelection {
                version: SELECTION_VERSION,
                selected_profile: Some(missing),
            })
            .unwrap(),
            "endpoint selection",
        )
        .unwrap();

        let loaded = EndpointCatalog::load_from_paths(&catalog_path, &selection_path).unwrap();
        assert_eq!(loaded.ssh[0].id, saved);
        assert_eq!(loaded.selected_profile, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacySavedSshEndpoint {
        id: ProfileId,
        label: String,
        target: String,
        session: String,
        enabled: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyEndpointCatalog {
        version: u32,
        #[serde(default)]
        selected_profile: Option<ProfileId>,
        #[serde(default)]
        ssh: Vec<LegacySavedSshEndpoint>,
    }

    fn sample_profile(enabled: bool, local_sessions: Option<Vec<&str>>) -> SavedSshEndpoint {
        let mut profile = SavedSshEndpoint::new("Build", "build", "agents").unwrap();
        profile.enabled = enabled;
        profile.local_sessions =
            local_sessions.map(|names| names.into_iter().map(str::to_string).collect());
        profile
    }

    fn write_catalog(path: &Path, body: &str) {
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn local_availability_matrix() {
        let cases = [
            ("omitted-enabled-default", true, None, "default", true, true),
            (
                "omitted-enabled-tradingdroid",
                true,
                None,
                "tradingdroid",
                true,
                true,
            ),
            (
                "omitted-disabled-default",
                false,
                None,
                "default",
                true,
                false,
            ),
            (
                "omitted-disabled-tradingdroid",
                false,
                None,
                "tradingdroid",
                true,
                false,
            ),
            (
                "empty-enabled-default",
                true,
                Some(vec![]),
                "default",
                false,
                false,
            ),
            (
                "empty-enabled-tradingdroid",
                true,
                Some(vec![]),
                "tradingdroid",
                false,
                false,
            ),
            (
                "empty-disabled-default",
                false,
                Some(vec![]),
                "default",
                false,
                false,
            ),
            (
                "default-only-enabled-default",
                true,
                Some(vec!["default"]),
                "default",
                true,
                true,
            ),
            (
                "default-only-enabled-tradingdroid",
                true,
                Some(vec!["default"]),
                "tradingdroid",
                false,
                false,
            ),
            (
                "default-only-disabled-default",
                false,
                Some(vec!["default"]),
                "default",
                true,
                false,
            ),
            (
                "tradingdroid-only-enabled-default",
                true,
                Some(vec!["tradingdroid"]),
                "default",
                false,
                false,
            ),
            (
                "tradingdroid-only-enabled-tradingdroid",
                true,
                Some(vec!["tradingdroid"]),
                "tradingdroid",
                true,
                true,
            ),
            (
                "tradingdroid-only-disabled-tradingdroid",
                false,
                Some(vec!["tradingdroid"]),
                "tradingdroid",
                true,
                false,
            ),
            (
                "both-enabled-default",
                true,
                Some(vec!["default", "tradingdroid"]),
                "default",
                true,
                true,
            ),
            (
                "both-enabled-tradingdroid",
                true,
                Some(vec!["default", "tradingdroid"]),
                "tradingdroid",
                true,
                true,
            ),
            (
                "both-enabled-other",
                true,
                Some(vec!["default", "tradingdroid"]),
                "other",
                false,
                false,
            ),
            (
                "both-disabled-default",
                false,
                Some(vec!["default", "tradingdroid"]),
                "default",
                true,
                false,
            ),
            (
                "case-sensitive-default",
                true,
                Some(vec!["default"]),
                "Default",
                false,
                false,
            ),
            (
                "future-name-enabled",
                true,
                Some(vec!["not-created-yet"]),
                "not-created-yet",
                true,
                true,
            ),
            (
                "future-name-other-context",
                true,
                Some(vec!["not-created-yet"]),
                "default",
                false,
                false,
            ),
        ];
        for (name, enabled, sessions, context, allowed, available) in cases {
            let profile = sample_profile(enabled, sessions);
            assert_eq!(
                profile.locally_allowed_in(context),
                allowed,
                "{name} locally_allowed_in"
            );
            assert_eq!(
                profile.is_available_in(context),
                available,
                "{name} is_available_in"
            );
            assert_eq!(
                profile.is_available_in(context),
                enabled && profile.locally_allowed_in(context),
                "{name} combined availability"
            );
        }
    }

    #[test]
    fn local_sessions_normalize_and_enforce_input_bounds() {
        let sorted = normalize_local_sessions(Some(&[
            "tradingdroid".into(),
            "default".into(),
            "default".into(),
        ]))
        .unwrap();
        assert_eq!(sorted, Some(vec!["default".into(), "tradingdroid".into()]));

        let accepted: Vec<String> = (0..MAX_LOCAL_SESSIONS)
            .map(|index| format!("session-{index:02}"))
            .collect();
        assert_eq!(
            normalize_local_sessions(Some(&accepted))
                .unwrap()
                .unwrap()
                .len(),
            MAX_LOCAL_SESSIONS
        );

        let mut too_many = accepted.clone();
        too_many.push("session-extra".into());
        assert!(normalize_local_sessions(Some(&too_many))
            .unwrap_err()
            .contains(&MAX_LOCAL_SESSIONS.to_string()));

        let mut duplicates_over_limit = vec!["default".into(); MAX_LOCAL_SESSIONS + 1];
        assert!(normalize_local_sessions(Some(&duplicates_over_limit)).is_err());
        duplicates_over_limit.pop();
        assert_eq!(
            normalize_local_sessions(Some(&duplicates_over_limit)).unwrap(),
            Some(vec!["default".into()])
        );

        let max_name = "a".repeat(64);
        assert_eq!(
            normalize_local_sessions(Some(std::slice::from_ref(&max_name))).unwrap(),
            Some(vec![max_name])
        );
        assert!(normalize_local_sessions(Some(&["a".repeat(65)])).is_err());
        assert_eq!(normalize_local_sessions(None).unwrap(), None);
        assert_eq!(
            normalize_local_sessions(Some(&[])).unwrap(),
            Some(Vec::new())
        );
    }

    #[test]
    fn local_sessions_reject_invalid_names_and_json_shapes() {
        let path = path("invalid-local-sessions");
        for (name, extra) in [
            ("empty", r#", "local_sessions": [""]"#),
            ("dot", r#", "local_sessions": ["."]"#),
            ("dotdot", r#", "local_sessions": [".."]"#),
            ("slash", r#", "local_sessions": ["a/b"]"#),
            ("whitespace", r#", "local_sessions": ["a b"]"#),
            ("control", ", \"local_sessions\": [\"a\\n\"]"),
            ("non-ascii", r#", "local_sessions": ["café"]"#),
            ("wildcard", r#", "local_sessions": ["*"]"#),
            ("scalar", r#", "local_sessions": "default""#),
            ("object", r#", "local_sessions": {"default": true}"#),
            ("mixed", r#", "local_sessions": ["default", 1]"#),
        ] {
            write_catalog(
                &path,
                &format!(
                    r#"{{
                      "version": 1,
                      "ssh": [{{
                        "id": "0123456789abcdef0123456789abcdef",
                        "label": "Build",
                        "target": "build",
                        "session": "default",
                        "enabled": true{extra}
                      }}]
                    }}"#
                ),
            );
            let error = EndpointCatalog::load_from_path(&path).unwrap_err();
            assert!(
                error.contains("session name")
                    || error.contains("stored endpoint catalog is invalid"),
                "{name}: {error}"
            );
        }
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn restricted_catalog_rejects_legacy_strict_reader() {
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("Build", "build", "agents").unwrap();
        let unrestricted = serde_json::to_value(&catalog).unwrap();
        assert!(unrestricted["ssh"][0].get("local_sessions").is_none());
        let legacy = serde_json::from_value::<LegacyEndpointCatalog>(unrestricted.clone()).unwrap();
        assert_eq!(legacy.version, 1);
        assert_eq!(legacy.ssh.len(), 1);
        assert_eq!(legacy.ssh[0].id, catalog.ssh[0].id);
        assert_eq!(legacy.ssh[0].label, "Build");
        assert_eq!(legacy.ssh[0].target, "build");
        assert_eq!(legacy.ssh[0].session, "agents");
        assert!(legacy.ssh[0].enabled);
        assert_eq!(legacy.selected_profile, None);

        catalog.ssh[0].local_sessions = Some(Vec::new());
        let empty = serde_json::to_value(&catalog).unwrap();
        assert_eq!(empty["ssh"][0]["local_sessions"], serde_json::json!([]));
        assert!(serde_json::from_value::<LegacyEndpointCatalog>(empty)
            .unwrap_err()
            .to_string()
            .contains("unknown field `local_sessions`"));

        catalog.ssh[0].local_sessions = Some(vec!["default".into()]);
        let restricted = serde_json::to_value(&catalog).unwrap();
        assert!(serde_json::from_value::<LegacyEndpointCatalog>(restricted)
            .unwrap_err()
            .to_string()
            .contains("unknown field `local_sessions`"));

        catalog.ssh[0].local_sessions = None;
        let cleared = serde_json::to_value(&catalog).unwrap();
        assert!(cleared["ssh"][0].get("local_sessions").is_none());
        serde_json::from_value::<LegacyEndpointCatalog>(cleared).unwrap();
    }

    #[test]
    fn stale_embedded_selection_preserves_valid_profiles() {
        let path = path("stale-embedded");
        let profile_id = "0123456789abcdef0123456789abcdef";
        let present = SavedSshEndpoint {
            id: ProfileId::parse(profile_id).unwrap(),
            label: "Build".into(),
            target: "build".into(),
            session: "default".into(),
            enabled: true,
            local_sessions: Some(vec!["default".into()]),
        };

        write_catalog(
            &path,
            r#"{
              "version": 1,
              "selected_profile": "not-a-profile-id",
              "ssh": [{
                "id": "0123456789abcdef0123456789abcdef",
                "label": "Build",
                "target": "build",
                "session": "default",
                "enabled": true
              }]
            }"#,
        );
        let malformed = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(malformed.ssh.len(), 1);
        assert_eq!(malformed.ssh[0].id.as_str(), profile_id);
        assert!(malformed.resolved_embedded_selection("default").is_none());
        assert!(malformed.validate().is_err());
        assert!(malformed.validate_profiles().is_ok());
        let original = std::fs::read(&path).unwrap();
        let _ = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let disabled = EndpointCatalog {
            selected_profile: Some(present.id.clone()),
            ssh: vec![SavedSshEndpoint {
                enabled: false,
                local_sessions: None,
                ..present.clone()
            }],
            ..EndpointCatalog::default()
        };
        assert!(disabled.validate_profiles().is_ok());
        assert!(disabled.validate().is_err());
        assert!(disabled.resolved_embedded_selection("default").is_none());

        let absent = EndpointCatalog {
            selected_profile: Some(ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap()),
            ssh: vec![present.clone()],
            ..EndpointCatalog::default()
        };
        assert!(absent.validate_profiles().is_ok());
        assert!(absent.resolved_embedded_selection("default").is_none());

        let disallowed = EndpointCatalog {
            selected_profile: Some(present.id.clone()),
            ssh: vec![present],
            ..EndpointCatalog::default()
        };
        assert!(disallowed.validate_profiles().is_ok());
        assert!(disallowed.validate().is_ok());
        assert!(disallowed.embedded_selection_is_globally_valid());
        assert!(disallowed.resolved_embedded_selection("default").is_some());
        assert!(disallowed
            .resolved_embedded_selection("tradingdroid")
            .is_none());

        disallowed.store_to_path(&path).unwrap();
        let reloaded = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(
            reloaded.selected_profile.as_ref().map(ProfileId::as_str),
            Some(profile_id)
        );

        disabled.store_to_path(&path).unwrap();
        let normalized = EndpointCatalog::load_from_path(&path).unwrap();
        assert_eq!(normalized.ssh.len(), 1);
        assert_eq!(normalized.selected_profile, None);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
