use std::collections::HashSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::ProfileId;

const CATALOG_VERSION: u32 = 1;
const SELECTION_VERSION: u32 = 1;
const MAX_CATALOG_BYTES: u64 = 64 * 1024;
const MAX_PROFILES: usize = 64;
const MAX_LABEL_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 1024;
const MAX_LOCAL_SESSIONS: usize = 64;
const CATALOG_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const CATALOG_LOCK_RETRY_SLEEP: Duration = Duration::from_millis(25);
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

    pub(crate) fn locally_allowed_in(&self, local_session: &str) -> bool {
        match &self.local_sessions {
            None => true,
            Some(sessions) => sessions.iter().any(|name| name == local_session),
        }
    }

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

#[derive(Debug)]
pub(crate) enum CatalogUpdateError {
    Mutation(String),
    Storage(String),
}

#[derive(Debug)]
pub(crate) enum AddProfileError {
    Load(String),
    Invalid(String),
    Prepare(io::Error),
    Save(String),
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
        Self::load_for_local_session(&crate::session::validated_local_session_name()?)
    }

    pub(crate) fn load_profiles() -> Result<Vec<SavedSshEndpoint>, String> {
        // Live clients keep their own selection, independent of other attached clients.
        Self::load_raw().map(|catalog| catalog.ssh)
    }

    pub(crate) fn load_raw() -> Result<Self, String> {
        Self::load_from_path(&catalog_path())
    }

    pub(crate) fn load_for_local_session(local_session: &str) -> Result<Self, String> {
        Self::load_for_local_session_from_paths(
            &catalog_path(),
            &selection_path(),
            &scoped_selection_path(local_session)?,
            local_session,
        )
    }

    fn load_for_local_session_from_paths(
        catalog_path: &Path,
        legacy_selection_path: &Path,
        scoped_selection_path: &Path,
        local_session: &str,
    ) -> Result<Self, String> {
        let mut catalog = Self::load_from_path(catalog_path)?;
        catalog.selected_profile = resolve_selected_profile(
            &catalog,
            local_session,
            scoped_selection_path,
            legacy_selection_path,
        );
        Ok(catalog)
    }

    pub(crate) fn selected_profile_for_local_session(
        &self,
        local_session: &str,
    ) -> Option<ProfileId> {
        resolve_selected_profile(
            self,
            local_session,
            &scoped_selection_path(local_session).ok()?,
            &selection_path(),
        )
    }

    fn persist_explicit_selection_to_path(
        &mut self,
        endpoint_id: &super::ClientEndpointId,
        local_session: &str,
        path: &Path,
    ) -> Result<(), String> {
        if !self.select_available_endpoint(endpoint_id, local_session) {
            return Err("selected SSH endpoint is absent, disabled, or unavailable".into());
        }
        self.store_selection_to_path(path)
    }

    pub(crate) fn apply_activation_selection_to_path(
        &mut self,
        endpoint_id: &super::ClientEndpointId,
        persist: bool,
        local_session: Option<&str>,
        selection_path: Option<&Path>,
    ) -> bool {
        if persist {
            let (Some(local_session), Some(path)) = (local_session, selection_path) else {
                return false;
            };
            if let Err(error) =
                self.persist_explicit_selection_to_path(endpoint_id, local_session, path)
            {
                tracing::warn!(%error, "failed to persist desired endpoint selection");
                return self.select_available_endpoint(endpoint_id, local_session);
            }
            true
        } else {
            self.select_endpoint(endpoint_id)
        }
    }

    pub(crate) fn update_profiles<T>(
        mutate: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, CatalogUpdateError> {
        Self::update_profiles_at(
            &catalog_path(),
            &catalog_lock_path(),
            CATALOG_LOCK_TIMEOUT,
            mutate,
        )
    }

    pub(crate) fn add_profile_after_prepare(
        label: String,
        target: String,
        session: String,
        prepare: impl FnOnce(&str, &str) -> io::Result<()>,
    ) -> Result<ProfileId, AddProfileError> {
        Self::add_profile_after_prepare_at(
            &catalog_path(),
            &catalog_lock_path(),
            CATALOG_LOCK_TIMEOUT,
            label,
            target,
            session,
            prepare,
        )
    }

    fn add_profile_after_prepare_at(
        catalog_path: &Path,
        lock_path: &Path,
        timeout: Duration,
        label: String,
        target: String,
        session: String,
        prepare: impl FnOnce(&str, &str) -> io::Result<()>,
    ) -> Result<ProfileId, AddProfileError> {
        let catalog = Self::load_from_path(catalog_path).map_err(AddProfileError::Load)?;
        catalog
            .clone()
            .add_ssh(label.clone(), &target, session.clone())
            .map_err(AddProfileError::Invalid)?;
        prepare(&target, &session).map_err(AddProfileError::Prepare)?;
        Self::update_profiles_at(catalog_path, lock_path, timeout, |catalog| {
            catalog.add_ssh(label, target, session)
        })
        .map_err(|error| match error {
            CatalogUpdateError::Mutation(error) => AddProfileError::Invalid(error),
            CatalogUpdateError::Storage(error) => AddProfileError::Save(error),
        })
    }

    fn update_profiles_at<T>(
        catalog_path: &Path,
        lock_path: &Path,
        timeout: Duration,
        mutate: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, CatalogUpdateError> {
        #[cfg(test)]
        run_lock_acquisition_boundary_hook();
        let _lock =
            acquire_catalog_lock(lock_path, timeout).map_err(CatalogUpdateError::Storage)?;
        let mut catalog =
            Self::load_from_path(catalog_path).map_err(CatalogUpdateError::Storage)?;
        let result = mutate(&mut catalog).map_err(CatalogUpdateError::Mutation)?;
        catalog
            .store_to_path(catalog_path)
            .map_err(CatalogUpdateError::Storage)?;
        Ok(result)
    }

    #[cfg(test)]
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

    pub(crate) fn select_available_endpoint(
        &mut self,
        endpoint_id: &super::ClientEndpointId,
        local_session: &str,
    ) -> bool {
        match endpoint_id {
            super::ClientEndpointId::Local => {
                self.select_local();
                true
            }
            super::ClientEndpointId::Ssh(profile_id) => {
                if !self.ssh.iter().any(|profile| {
                    &profile.id == profile_id && profile.is_available_in(local_session)
                }) {
                    return false;
                }
                self.selected_profile = Some(profile_id.clone());
                true
            }
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

    pub(crate) fn set_local_sessions(
        &mut self,
        id: &ProfileId,
        local_sessions: Option<Vec<String>>,
    ) -> Result<bool, String> {
        let Some(profile) = self.ssh.iter_mut().find(|profile| &profile.id == id) else {
            return Ok(false);
        };
        profile.local_sessions = normalize_local_sessions(local_sessions.as_deref())?;
        Ok(true)
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
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read endpoint selection: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect endpoint selection: {error}"))?;
    if metadata.len() > MAX_CATALOG_BYTES {
        return Err("endpoint selection exceeds the storage limit".into());
    }
    let mut content = Vec::new();
    file.take(MAX_CATALOG_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|error| format!("failed to read endpoint selection: {error}"))?;
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

fn catalog_lock_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join(".endpoints.lock")
}

fn selection_path() -> PathBuf {
    crate::config::state_dir()
        .join("client")
        .join("endpoint-selection.json")
}

pub(crate) fn scoped_selection_path(local_session: &str) -> Result<PathBuf, String> {
    crate::session::validate_name(local_session)?;
    Ok(crate::config::state_dir()
        .join("client")
        .join("endpoint-selections")
        .join(format!("{local_session}.json")))
}

fn resolve_selected_profile(
    catalog: &EndpointCatalog,
    local_session: &str,
    scoped_selection_path: &Path,
    legacy_selection_path: &Path,
) -> Option<ProfileId> {
    let candidate = match load_selection_from_path(scoped_selection_path) {
        Ok(Some(selection)) => selection.selected_profile,
        Ok(None) if local_session == crate::session::DEFAULT_SESSION_NAME => {
            match load_selection_from_path(legacy_selection_path) {
                Ok(Some(selection)) => selection.selected_profile,
                Ok(None) => catalog.selected_profile.clone(),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %legacy_selection_path.display(),
                        "saved endpoint selection is unavailable; using Local"
                    );
                    None
                }
            }
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(
                %error,
                path = %scoped_selection_path.display(),
                "saved endpoint selection is unavailable; using Local"
            );
            None
        }
    };
    let mut resolved = catalog.clone();
    resolved.selected_profile = candidate;
    resolved.resolved_embedded_selection(local_session).cloned()
}

#[cfg(test)]
thread_local! {
    static LOCK_ACQUISITION_BOUNDARY_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_lock_acquisition_boundary_hook(hook: impl FnOnce() + 'static) {
    LOCK_ACQUISITION_BOUNDARY_HOOK.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_lock_acquisition_boundary_hook() {
    if let Some(hook) = LOCK_ACQUISITION_BOUNDARY_HOOK.with(|cell| cell.borrow_mut().take()) {
        hook();
    }
}

fn acquire_catalog_lock(lock_path: &Path, timeout: Duration) -> Result<File, String> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create endpoint catalog directory: {error}"))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|error| format!("failed to open endpoint catalog lock: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err("endpoint catalog is busy; try again".into());
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining.min(CATALOG_LOCK_RETRY_SLEEP));
            }
            Err(TryLockError::Error(error)) => {
                return Err(format!("failed to lock endpoint catalog: {error}"));
            }
        }
    }
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

    fn lock_path_for(catalog_path: &Path) -> PathBuf {
        catalog_path.with_file_name(".endpoints.lock")
    }

    fn update_at<T>(
        catalog_path: &Path,
        mutate: impl FnOnce(&mut EndpointCatalog) -> Result<T, String>,
    ) -> Result<T, CatalogUpdateError> {
        EndpointCatalog::update_profiles_at(
            catalog_path,
            &lock_path_for(catalog_path),
            CATALOG_LOCK_TIMEOUT,
            mutate,
        )
    }

    #[test]
    fn catalog_mutations_never_copy_scoped_selection() {
        let catalog_path = path("raw-admin-selection");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        std::fs::create_dir_all(parent.join("endpoint-selections")).unwrap();
        let legacy_selection = parent.join("endpoint-selection.json");
        let scoped_selection = parent.join("endpoint-selections").join("default.json");
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "one", "default").unwrap();
        let second = catalog.add_ssh("Two", "two", "default").unwrap();
        catalog.selected_profile = Some(first.clone());
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(
            &legacy_selection,
            b"{\"version\":1,\"selected_profile\":null}",
        )
        .unwrap();
        std::fs::write(
            &scoped_selection,
            b"{\"version\":1,\"selected_profile\":null}",
        )
        .unwrap();
        let legacy_before = std::fs::read(&legacy_selection).unwrap();
        let scoped_before = std::fs::read(&scoped_selection).unwrap();

        update_at(&catalog_path, |catalog| {
            catalog.rename_ssh(&first, "Renamed").map(|_| ())
        })
        .unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.ssh[1].local_sessions = Some(vec!["default".into()]);
            Ok(())
        })
        .unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.set_enabled(&second, false);
            Ok(())
        })
        .unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.set_enabled(&second, true);
            Ok(())
        })
        .unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.add_ssh("Three", "three", "default").map(|_| ())
        })
        .unwrap();
        update_at(&catalog_path, |catalog| {
            assert!(catalog.remove_ssh(&second));
            Ok(())
        })
        .unwrap();

        let loaded = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(loaded.selected_profile.as_ref(), Some(&first));
        assert_eq!(loaded.ssh[0].label, "Renamed");
        assert_eq!(std::fs::read(&legacy_selection).unwrap(), legacy_before);
        assert_eq!(std::fs::read(&scoped_selection).unwrap(), scoped_before);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn catalog_writes_normalize_only_globally_invalid_embedded_selection() {
        let catalog_path = path("raw-write-normalize");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        let present = SavedSshEndpoint {
            id: ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            label: "Build".into(),
            target: "build".into(),
            session: "default".into(),
            enabled: true,
            local_sessions: Some(vec!["default".into()]),
        };
        let catalog = EndpointCatalog {
            selected_profile: Some(present.id.clone()),
            ssh: vec![present.clone()],
            ..EndpointCatalog::default()
        };
        catalog.store_to_path(&catalog_path).unwrap();
        let before = std::fs::read(&catalog_path).unwrap();
        let _ = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(std::fs::read(&catalog_path).unwrap(), before);

        update_at(&catalog_path, |_| Ok(())).unwrap();
        let kept = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(kept.selected_profile.as_ref(), Some(&present.id));

        write_catalog(
            &catalog_path,
            r#"{
              "version": 1,
              "selected_profile": "fedcba9876543210fedcba9876543210",
              "ssh": [{
                "id": "0123456789abcdef0123456789abcdef",
                "label": "Build",
                "target": "build",
                "session": "default",
                "enabled": true,
                "local_sessions": ["default"]
              }]
            }"#,
        );
        update_at(&catalog_path, |_| Ok(())).unwrap();
        let cleared_absent = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(cleared_absent.selected_profile, None);
        assert_eq!(cleared_absent.ssh.len(), 1);

        write_catalog(
            &catalog_path,
            r#"{
              "version": 1,
              "selected_profile": "0123456789abcdef0123456789abcdef",
              "ssh": [{
                "id": "0123456789abcdef0123456789abcdef",
                "label": "Build",
                "target": "build",
                "session": "default",
                "enabled": false
              }]
            }"#,
        );
        update_at(&catalog_path, |_| Ok(())).unwrap();
        let cleared_disabled = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(cleared_disabled.selected_profile, None);

        write_catalog(
            &catalog_path,
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
        update_at(&catalog_path, |_| Ok(())).unwrap();
        let cleared_malformed = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(cleared_malformed.selected_profile, None);
        assert_eq!(cleared_malformed.ssh.len(), 1);

        let unchanged = std::fs::read(&catalog_path).unwrap();
        let failed: Result<(), CatalogUpdateError> =
            update_at(&catalog_path, |_| Err("mutation failed".into()));
        assert!(matches!(failed, Err(CatalogUpdateError::Mutation(_))));
        assert_eq!(std::fs::read(&catalog_path).unwrap(), unchanged);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn clearing_restrictions_restores_old_reader_valid_catalog() {
        let catalog_path = path("clear-restrictions");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        let first = SavedSshEndpoint {
            id: ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
            label: "One".into(),
            target: "one".into(),
            session: "default".into(),
            enabled: true,
            local_sessions: Some(vec!["default".into()]),
        };
        let second = SavedSshEndpoint {
            id: ProfileId::parse("fedcba9876543210fedcba9876543210").unwrap(),
            label: "Two".into(),
            target: "two".into(),
            session: "default".into(),
            enabled: false,
            local_sessions: Some(Vec::new()),
        };
        write_catalog(
            &catalog_path,
            &format!(
                r#"{{
                  "version": 1,
                  "selected_profile": "{}",
                  "ssh": [{{
                    "id": "{}",
                    "label": "One",
                    "target": "one",
                    "session": "default",
                    "enabled": true,
                    "local_sessions": ["default"]
                  }}, {{
                    "id": "{}",
                    "label": "Two",
                    "target": "two",
                    "session": "default",
                    "enabled": false,
                    "local_sessions": []
                  }}]
                }}"#,
                second.id, first.id, second.id
            ),
        );

        update_at(&catalog_path, |catalog| {
            assert!(catalog.remove_ssh(&second.id));
            catalog.ssh[0].local_sessions = None;
            Ok(())
        })
        .unwrap();

        let encoded = std::fs::read_to_string(&catalog_path).unwrap();
        assert!(!encoded.contains("local_sessions"));
        let loaded = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(loaded.selected_profile, None);
        loaded.validate().unwrap();
        serde_json::from_str::<LegacyEndpointCatalog>(&encoded).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn catalog_rmw_preserves_concurrent_mutations() {
        let catalog_path = path("rmw-concurrent");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        let mut catalog = EndpointCatalog::default();
        let first = catalog.add_ssh("One", "one", "default").unwrap();
        let second = catalog.add_ssh("Two", "two", "default").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (at_boundary_tx, at_boundary_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let wait = Duration::from_secs(2);
        let incumbent_path = catalog_path.clone();
        let first_id = first.clone();
        let incumbent = std::thread::spawn(move || {
            let result = update_at(&incumbent_path, |catalog| {
                holding_tx.send(()).unwrap();
                at_boundary_rx.recv_timeout(wait).unwrap();
                catalog.rename_ssh(&first_id, "Renamed").map(|_| ())
            });
            released_tx.send(()).unwrap();
            result
        });
        holding_rx.recv_timeout(wait).unwrap();
        let second_path = catalog_path.clone();
        let second_id = second.clone();
        let waiter = std::thread::spawn(move || {
            set_lock_acquisition_boundary_hook(move || {
                at_boundary_tx.send(()).unwrap();
                released_rx.recv_timeout(wait).unwrap();
            });
            update_at(&second_path, |catalog| {
                catalog.set_enabled(&second_id, false);
                Ok(())
            })
        });
        incumbent.join().unwrap().unwrap();
        waiter.join().unwrap().unwrap();
        let loaded = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(loaded.ssh[0].label, "Renamed");
        assert!(!loaded.ssh[1].enabled);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn catalog_lock_timeout_leaves_catalog_unchanged() {
        let catalog_path = path("lock-timeout");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        let mut catalog = EndpointCatalog::default();
        catalog.add_ssh("One", "one", "default").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let before = std::fs::read(&catalog_path).unwrap();
        let lock_path = lock_path_for(&catalog_path);
        let held = acquire_catalog_lock(&lock_path, CATALOG_LOCK_TIMEOUT).unwrap();
        let error = EndpointCatalog::update_profiles_at(
            &catalog_path,
            &lock_path,
            Duration::from_millis(40),
            |catalog| {
                catalog.ssh[0].label = "Changed".into();
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, CatalogUpdateError::Storage(message) if message.contains("busy")));
        assert_eq!(std::fs::read(&catalog_path).unwrap(), before);
        drop(held);
        update_at(&catalog_path, |catalog| {
            catalog.ssh[0].label = "Changed".into();
            Ok(())
        })
        .unwrap();
        let loaded = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(loaded.ssh[0].label, "Changed");
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn catalog_add_preparation_does_not_hold_lock() {
        let catalog_path = path("add-prepare");
        let parent = catalog_path.parent().unwrap();
        let _ = std::fs::remove_dir_all(parent);
        let mut catalog = EndpointCatalog::default();
        let existing = catalog.add_ssh("One", "one", "default").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let lock_path = lock_path_for(&catalog_path);
        let wait = Duration::from_secs(2);
        let (preparing_tx, preparing_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let add_path = catalog_path.clone();
        let add_lock = lock_path.clone();
        let adder = std::thread::spawn(move || {
            EndpointCatalog::add_profile_after_prepare_at(
                &add_path,
                &add_lock,
                CATALOG_LOCK_TIMEOUT,
                "Two".into(),
                "two".into(),
                "default".into(),
                |_, _| {
                    preparing_tx.send(()).unwrap();
                    continue_rx.recv_timeout(wait).unwrap();
                    Ok(())
                },
            )
        });
        preparing_rx.recv_timeout(wait).unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.rename_ssh(&existing, "Renamed").map(|_| ())
        })
        .unwrap();
        continue_tx.send(()).unwrap();
        adder.join().unwrap().unwrap();

        let loaded = EndpointCatalog::load_from_path(&catalog_path).unwrap();
        assert_eq!(loaded.ssh.len(), 2);
        assert_eq!(loaded.ssh[0].label, "Renamed");
        assert_eq!(loaded.ssh[1].label, "Two");

        update_at(&catalog_path, |catalog| {
            while catalog.ssh.len() < MAX_PROFILES - 1 {
                catalog.add_ssh(
                    format!("Fill{}", catalog.ssh.len()),
                    format!("fill{}", catalog.ssh.len()),
                    "default",
                )?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            EndpointCatalog::load_from_path(&catalog_path)
                .unwrap()
                .ssh
                .len(),
            MAX_PROFILES - 1
        );

        let (full_prep_tx, full_prep_rx) = std::sync::mpsc::channel();
        let (full_go_tx, full_go_rx) = std::sync::mpsc::channel();
        let overflow_path = catalog_path.clone();
        let overflow_lock = lock_path;
        let overflow = std::thread::spawn(move || {
            EndpointCatalog::add_profile_after_prepare_at(
                &overflow_path,
                &overflow_lock,
                CATALOG_LOCK_TIMEOUT,
                "Overflow".into(),
                "overflow".into(),
                "default".into(),
                |_, _| {
                    full_prep_tx.send(()).unwrap();
                    full_go_rx.recv_timeout(wait).unwrap();
                    Ok(())
                },
            )
        });
        full_prep_rx.recv_timeout(wait).unwrap();
        update_at(&catalog_path, |catalog| {
            catalog.add_ssh("Last", "last", "default").map(|_| ())
        })
        .unwrap();
        let after_last = std::fs::read(&catalog_path).unwrap();
        assert_eq!(
            EndpointCatalog::load_from_path(&catalog_path)
                .unwrap()
                .ssh
                .len(),
            MAX_PROFILES
        );
        full_go_tx.send(()).unwrap();
        assert!(matches!(
            overflow.join().unwrap(),
            Err(AddProfileError::Invalid(_))
        ));
        assert_eq!(std::fs::read(&catalog_path).unwrap(), after_last);
        std::fs::remove_dir_all(parent).unwrap();
    }

    fn scoped_fixture(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let catalog_path = path(name);
        let parent = catalog_path.parent().unwrap().to_path_buf();
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(parent.join("endpoint-selections")).unwrap();
        let legacy = parent.join("endpoint-selection.json");
        let scoped = |session: &str| {
            parent
                .join("endpoint-selections")
                .join(format!("{session}.json"))
        };
        (
            catalog_path,
            legacy,
            scoped("default"),
            scoped("tradingdroid"),
        )
    }

    fn load_scoped(
        catalog_path: &Path,
        legacy: &Path,
        scoped: &Path,
        session: &str,
    ) -> EndpointCatalog {
        EndpointCatalog::load_for_local_session_from_paths(catalog_path, legacy, scoped, session)
            .unwrap()
    }

    #[test]
    fn scoped_selection_default_only_import_is_read_only() {
        let (catalog_path, legacy, default_scoped, named_scoped) = scoped_fixture("scoped-import");
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.selected_profile = Some(id.clone());
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(
            &legacy,
            format!(r#"{{"version":1,"selected_profile":"{id}"}}"#),
        )
        .unwrap();
        let catalog_before = std::fs::read(&catalog_path).unwrap();
        let legacy_before = std::fs::read(&legacy).unwrap();

        let default = load_scoped(&catalog_path, &legacy, &default_scoped, "default");
        assert_eq!(default.selected_profile.as_ref(), Some(&id));
        let named = load_scoped(&catalog_path, &legacy, &named_scoped, "tradingdroid");
        assert_eq!(named.selected_profile, None);
        assert!(!default_scoped.exists());
        assert!(!named_scoped.exists());
        assert_eq!(std::fs::read(&catalog_path).unwrap(), catalog_before);
        assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn scoped_local_and_malformed_selection_do_not_resurrect_legacy() {
        let (catalog_path, legacy, default_scoped, _) = scoped_fixture("scoped-override");
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.selected_profile = Some(id.clone());
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(
            &legacy,
            format!(r#"{{"version":1,"selected_profile":"{id}"}}"#),
        )
        .unwrap();
        std::fs::write(
            &default_scoped,
            b"{\"version\":1,\"selected_profile\":null}",
        )
        .unwrap();
        let loaded = load_scoped(&catalog_path, &legacy, &default_scoped, "default");
        assert_eq!(loaded.selected_profile, None);

        std::fs::write(&default_scoped, b"not json").unwrap();
        let malformed = load_scoped(&catalog_path, &legacy, &default_scoped, "default");
        assert_eq!(malformed.selected_profile, None);

        std::fs::write(
            &default_scoped,
            r#"{"version":1,"selected_profile":"fedcba9876543210fedcba9876543210"}"#,
        )
        .unwrap();
        let absent = load_scoped(&catalog_path, &legacy, &default_scoped, "default");
        assert_eq!(absent.selected_profile, None);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn scoped_selection_writes_are_isolated() {
        let (catalog_path, legacy, default_scoped, named_scoped) = scoped_fixture("scoped-write");
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        std::fs::write(&legacy, b"{\"version\":1,\"selected_profile\":null}").unwrap();
        let catalog_before = std::fs::read(&catalog_path).unwrap();
        let legacy_before = std::fs::read(&legacy).unwrap();

        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Ssh(id.clone()),
            true,
            Some("default"),
            Some(&default_scoped),
        ));
        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Local,
            true,
            Some("tradingdroid"),
            Some(&named_scoped),
        ));

        assert_eq!(
            load_selection_from_path(&default_scoped)
                .unwrap()
                .unwrap()
                .selected_profile,
            Some(id)
        );
        assert_eq!(
            load_selection_from_path(&named_scoped)
                .unwrap()
                .unwrap()
                .selected_profile,
            None
        );
        assert_eq!(std::fs::read(&catalog_path).unwrap(), catalog_before);
        assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn automatic_activations_preserve_preference_files() {
        let (catalog_path, legacy, default_scoped, _) = scoped_fixture("preserve-write");
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        catalog.store_to_path(&catalog_path).unwrap();
        let catalog_before = std::fs::read(&catalog_path).unwrap();
        assert!(!legacy.exists());
        assert!(!default_scoped.exists());
        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Ssh(id.clone()),
            false,
            Some("default"),
            Some(&default_scoped),
        ));
        assert!(!legacy.exists());
        assert!(!default_scoped.exists());
        assert_eq!(std::fs::read(&catalog_path).unwrap(), catalog_before);
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn explicit_activation_persists_before_handoff() {
        let (catalog_path, legacy, default_scoped, _) = scoped_fixture("explicit-write");
        let mut catalog = EndpointCatalog::default();
        let id = catalog.add_ssh("Build", "build", "agents").unwrap();
        let disabled = catalog.add_ssh("Off", "off", "agents").unwrap();
        catalog.set_enabled(&disabled, false);
        catalog.store_to_path(&catalog_path).unwrap();
        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Ssh(id.clone()),
            true,
            Some("default"),
            Some(&default_scoped),
        ));
        let first = std::fs::read(&default_scoped).unwrap();
        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Ssh(id.clone()),
            true,
            Some("default"),
            Some(&default_scoped),
        ));
        assert!(catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Local,
            true,
            Some("default"),
            Some(&default_scoped),
        ));
        assert_eq!(
            load_selection_from_path(&default_scoped)
                .unwrap()
                .unwrap()
                .selected_profile,
            None
        );
        assert_ne!(std::fs::read(&default_scoped).unwrap(), first);
        assert!(!catalog.apply_activation_selection_to_path(
            &super::super::ClientEndpointId::Ssh(disabled),
            true,
            Some("default"),
            Some(&default_scoped),
        ));
        assert!(!legacy.exists());
        std::fs::remove_dir_all(catalog_path.parent().unwrap()).unwrap();
    }
}
