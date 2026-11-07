use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{EntraError, Result};

const SERVICE_NAME: &str = "entra";
const TOKEN_PREFIX: &str = "entra:token:";
#[cfg(target_os = "macos")]
const ITEM_DESCRIPTION: &str = "Microsoft Entra ID access token";
const MAX_CHUNKS: usize = 128;
// Serialises credential access across `entra` processes on Windows. The lock
// covers storage operations only, never a network refresh, so the wait is
// short unless another process has stopped part way through one.
const LOCK_FILE: &str = "credentials.lock";
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// Windows Credential Manager limits one credential blob to 2560 bytes. Graph
/// access and refresh tokens routinely exceed that once serialized together.
#[cfg(windows)]
const CHUNK_BYTES: Option<usize> = Some(2560);
#[cfg(not(windows))]
const CHUNK_BYTES: Option<usize> = None;

pub trait CredentialStore: Send + Sync {
    fn get_password(&self, key: &str) -> Result<Option<String>>;
    fn set_password(&self, key: &str, value: &str) -> Result<()>;
    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<bool>;

    /// Locks the store against other processes until the returned guard is
    /// dropped. A store whose single operations are already atomic needs no
    /// lock and returns `None`.
    fn lock(&self, _mode: LockMode) -> Result<Option<CredentialLock>> {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Reading: any number of readers, but no writer.
    Shared,
    /// Writing or deleting: no other reader or writer.
    Exclusive,
}

/// An operating-system file lock, released when dropped. Windows Credential
/// Manager has no transactions, and a chunked credential spans several
/// entries, so two processes refreshing one account at once could otherwise
/// interleave their chunks, and a reader could follow a header to chunks that
/// a writer is deleting.
#[derive(Debug)]
pub struct CredentialLock {
    _file: File,
}

impl CredentialLock {
    pub fn acquire(path: &Path, mode: LockMode, wait: Duration) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                EntraError::from(error).context(format!(
                    "creating the directory for the credential lock file {}",
                    path.display()
                ))
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                EntraError::from(error).context(format!(
                    "opening the credential lock file {}",
                    path.display()
                ))
            })?;
        let deadline = Instant::now() + wait;
        loop {
            let attempt = match mode {
                LockMode::Shared => file.try_lock_shared(),
                LockMode::Exclusive => file.try_lock(),
            };
            match attempt {
                Ok(()) => return Ok(Self { _file: file }),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(EntraError::CredentialLockBusy {
                        path: path.display().to_string(),
                        seconds: wait.as_secs(),
                    });
                }
                Err(TryLockError::Error(error)) => {
                    return Err(EntraError::from(error).context(format!(
                        "locking the credential lock file {}",
                        path.display()
                    )));
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct KeyringStore;

impl KeyringStore {
    fn entry(key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, key).map_err(Into::into)
    }
}

#[cfg(any(target_os = "macos", test))]
fn item_label(key: &str) -> String {
    match key.strip_prefix(TOKEN_PREFIX) {
        Some(account) if !account.is_empty() => format!("entra — {account}"),
        _ => "entra (Microsoft Entra ID CLI)".to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn set_macos_item_metadata(key: &str) -> Result<()> {
    use security_framework::item::{update_item, ItemClass, ItemSearchOptions, ItemUpdateOptions};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    let keychain =
        SecKeychain::default_for_domain(SecPreferencesDomain::User).map_err(|error| {
            EntraError::message(format!("opening the macOS user keychain: {error}"))
        })?;
    let mut search = ItemSearchOptions::new();
    search
        .keychains(&[keychain])
        .class(ItemClass::generic_password())
        .service(SERVICE_NAME)
        .account(key);

    let mut update = ItemUpdateOptions::new();
    update
        .set_label(item_label(key))
        .set_description(ITEM_DESCRIPTION);

    update_item(&search, &update).map_err(|error| {
        EntraError::message(format!(
            "labelling the macOS keychain item for {key:?}: {error}"
        ))
    })
}

fn absent_as_none<T>(result: keyring::Result<T>, operation: &str) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(EntraError::Keyring(error).context(operation)),
    }
}

impl CredentialStore for KeyringStore {
    fn get_password(&self, key: &str) -> Result<Option<String>> {
        absent_as_none(
            Self::entry(key)?.get_password(),
            "retrieving stored credential",
        )
    }

    fn set_password(&self, key: &str, value: &str) -> Result<()> {
        // set_password updates in place. Deleting first would replace the
        // macOS keychain item and discard its existing "Always Allow" ACL.
        Self::entry(key)?.set_password(value)?;
        // keyring's macOS backend intentionally ignores attributes other than
        // service and account. Add a human-readable label so the authorisation
        // dialog identifies both this CLI and the account being unlocked.
        #[cfg(target_os = "macos")]
        set_macos_item_metadata(key)?;
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        absent_as_none(
            Self::entry(key)?.get_secret(),
            "retrieving stored credential",
        )
    }

    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        Self::entry(key)?.set_secret(value)?;
        #[cfg(target_os = "macos")]
        set_macos_item_metadata(key)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool> {
        Ok(absent_as_none(
            Self::entry(key)?.delete_credential(),
            "deleting stored credential",
        )?
        .is_some())
    }

    /// Only chunked storage spans several entries; a single keychain or
    /// keyutils item is replaced in one operation and needs no lock.
    fn lock(&self, mode: LockMode) -> Result<Option<CredentialLock>> {
        if CHUNK_BYTES.is_none() {
            return Ok(None);
        }
        CredentialLock::acquire(&credential_lock_path()?, mode, LOCK_WAIT).map(Some)
    }
}

/// The lock file for this user's credentials. It is deliberately not under
/// the configuration directory: `ENTRA_CONFIG_DIR` moves that, but not the
/// credential store, and two processes guarding the same credentials must
/// always meet at the same lock.
fn credential_lock_path() -> Result<std::path::PathBuf> {
    dirs::data_local_dir()
        .map(|root| root.join("entra").join(LOCK_FILE))
        .ok_or_else(|| EntraError::message("could not determine the user's local data directory"))
}

/// Chunks live in one of two slots so that a rewrite never touches the chunks
/// the current header points at. Slot 0 uses the original `<key>:<n>` names,
/// which keeps headers written before slots existed readable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkHeader {
    chunks: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    slot: u8,
}

fn is_zero(slot: &u8) -> bool {
    *slot == 0
}

const SLOTS: [u8; 2] = [0, 1];

pub fn store_value(store: &dyn CredentialStore, key: &str, value: &str) -> Result<()> {
    let _lock = store.lock(LockMode::Exclusive)?;
    store_value_with_chunk_size(store, key, value, CHUNK_BYTES)
}

pub fn get_value(store: &dyn CredentialStore, key: &str) -> Result<String> {
    let _lock = store.lock(LockMode::Shared)?;
    let primary = store
        .get_password(key)?
        .ok_or_else(|| EntraError::message(format!("no stored credential exists for {key:?}")))?;
    let value = match parse_chunk_header(&primary)? {
        Some(header) => read_chunks(store, key, header.slot, header.chunks)?,
        None => primary,
    };
    Ok(value)
}

pub fn delete_value(store: &dyn CredentialStore, key: &str) -> Result<()> {
    let _lock = store.lock(LockMode::Exclusive)?;
    if CHUNK_BYTES.is_some() {
        delete_all_chunks(store, key)?;
    }
    store.delete(key)?;
    Ok(())
}

fn delete_all_chunks(store: &dyn CredentialStore, key: &str) -> Result<()> {
    for slot in SLOTS {
        delete_chunks(store, key, slot, 0)?;
    }
    Ok(())
}

fn chunk_key(key: &str, slot: u8, index: usize) -> String {
    match slot {
        0 => format!("{key}:{index}"),
        _ => format!("{key}:s{slot}:{index}"),
    }
}

fn store_value_with_chunk_size(
    store: &dyn CredentialStore,
    key: &str,
    value: &str,
    chunk_bytes: Option<usize>,
) -> Result<()> {
    match chunk_bytes {
        None => store.set_password(key, value),
        Some(0) => Err(EntraError::message("credential chunk size cannot be zero")),
        Some(size) => {
            let chunks: Vec<_> = value.as_bytes().chunks(size).collect();
            if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
                return Err(EntraError::message(format!(
                    "credential needs {} chunks; supported range is 1..={MAX_CHUNKS}",
                    chunks.len()
                )));
            }
            let previous = stored_header(store, key)?;
            // Write into the slot the current header does not use, so a
            // failure part way leaves the stored credential intact.
            let slot = match &previous {
                Some(header) if header.slot == 0 => 1,
                _ => 0,
            };
            for (index, chunk) in chunks.iter().enumerate() {
                store.set_secret(&chunk_key(key, slot, index), chunk)?;
            }
            // An earlier interrupted write may have left longer data here.
            delete_chunks(store, key, slot, chunks.len())?;
            let header = serde_json::to_string(&ChunkHeader {
                chunks: chunks.len(),
                slot,
            })?;
            store.set_password(key, &header)?;
            // The new header is live; the other slot now holds only old data.
            delete_chunks(store, key, 1 - slot, 0)
        }
    }
}

fn parse_chunk_header(value: &str) -> Result<Option<ChunkHeader>> {
    let Ok(header) = serde_json::from_str::<ChunkHeader>(value) else {
        return Ok(None);
    };
    if header.chunks == 0 || header.chunks > MAX_CHUNKS {
        return Err(EntraError::message(format!(
            "stored credential has invalid chunk count {}",
            header.chunks
        )));
    }
    if !SLOTS.contains(&header.slot) {
        return Err(EntraError::message(format!(
            "stored credential has invalid chunk slot {}",
            header.slot
        )));
    }
    Ok(Some(header))
}

/// The current header, or `None` when there is no entry, the entry is a
/// legacy single value, or its header is unusable and will be overwritten.
fn stored_header(store: &dyn CredentialStore, key: &str) -> Result<Option<ChunkHeader>> {
    match store.get_password(key)? {
        Some(primary) => Ok(parse_chunk_header(&primary).ok().flatten()),
        None => Ok(None),
    }
}

fn read_chunks(store: &dyn CredentialStore, key: &str, slot: u8, count: usize) -> Result<String> {
    let mut bytes = Vec::new();
    for index in 0..count {
        let chunk = store
            .get_secret(&chunk_key(key, slot, index))?
            .ok_or_else(|| {
                EntraError::message(format!(
                    "stored credential is incomplete (chunk {index} of {count} is missing); run 'entra auth login' again"
                ))
            })?;
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes)
        .map_err(|error| EntraError::message(format!("stored credential is not UTF-8: {error}")))
}

/// Delete every chunk in `slot` from `start` to the bound. The sweep does not
/// stop at the first absent entry, because an interrupted cleanup can leave
/// later chunks behind a gap, and those hold pieces of a refresh token.
fn delete_chunks(store: &dyn CredentialStore, key: &str, slot: u8, start: usize) -> Result<()> {
    for index in start..MAX_CHUNKS {
        store.delete(&chunk_key(key, slot, index))?;
    }
    Ok(())
}

pub fn token_key(email: &str) -> String {
    format!("{TOKEN_PREFIX}{}", email.to_ascii_lowercase())
}

#[cfg(test)]
pub mod test_support {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    pub struct MemoryStore {
        values: Mutex<BTreeMap<String, Vec<u8>>>,
        locks: Mutex<Vec<LockMode>>,
    }

    impl MemoryStore {
        pub fn remove(&self, key: &str) {
            self.values.lock().unwrap().remove(key);
        }

        pub fn keys(&self) -> Vec<String> {
            self.values.lock().unwrap().keys().cloned().collect()
        }

        /// The lock modes requested so far, in order.
        pub fn locks(&self) -> Vec<LockMode> {
            self.locks.lock().unwrap().clone()
        }
    }

    impl CredentialStore for MemoryStore {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.get_secret(key)?
                .map(String::from_utf8)
                .transpose()
                .map_err(|error| EntraError::message(error.to_string()))
        }

        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            self.set_secret(key, value.as_bytes())
        }

        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }

        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            self.values
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<bool> {
            Ok(self.values.lock().unwrap().remove(key).is_some())
        }

        fn lock(&self, mode: LockMode) -> Result<Option<CredentialLock>> {
            self.locks.lock().unwrap().push(mode);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemoryStore;
    use super::*;

    #[test]
    fn token_item_label_names_the_account() {
        assert_eq!(
            item_label("entra:token:someone@example.com"),
            "entra — someone@example.com"
        );
    }

    #[test]
    fn unknown_or_empty_keys_still_have_a_useful_item_label() {
        for key in ["", "profile-index", "entra:token:"] {
            assert_eq!(item_label(key), "entra (Microsoft Entra ID CLI)");
        }
    }

    #[test]
    fn writes_and_deletes_lock_exclusively_and_reads_share() {
        let store = MemoryStore::default();
        store_value(&store, "account", "value").unwrap();
        get_value(&store, "account").unwrap();
        delete_value(&store, "account").unwrap();
        assert_eq!(
            store.locks(),
            [LockMode::Exclusive, LockMode::Shared, LockMode::Exclusive]
        );
    }

    /// A store that locks a real file and checks, inside every storage
    /// operation, that the lock is still held.
    struct LockCheckingStore {
        inner: MemoryStore,
        path: std::path::PathBuf,
    }

    impl LockCheckingStore {
        fn assert_locked(&self) {
            assert!(
                CredentialLock::acquire(&self.path, LockMode::Exclusive, Duration::ZERO).is_err(),
                "a storage operation ran without the credential lock"
            );
        }
    }

    impl CredentialStore for LockCheckingStore {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.assert_locked();
            self.inner.get_password(key)
        }

        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            self.assert_locked();
            self.inner.set_password(key, value)
        }

        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.assert_locked();
            self.inner.get_secret(key)
        }

        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            self.assert_locked();
            self.inner.set_secret(key, value)
        }

        fn delete(&self, key: &str) -> Result<bool> {
            self.assert_locked();
            self.inner.delete(key)
        }

        fn lock(&self, mode: LockMode) -> Result<Option<CredentialLock>> {
            CredentialLock::acquire(&self.path, mode, Duration::from_secs(1)).map(Some)
        }
    }

    #[test]
    fn every_storage_operation_runs_while_the_lock_is_held() {
        let directory = tempfile::tempdir().unwrap();
        let store = LockCheckingStore {
            inner: MemoryStore::default(),
            path: directory.path().join(LOCK_FILE),
        };
        let value = "x".repeat(10);
        // A chunk size of four splits the value across slots, as on Windows.
        {
            let _lock = store.lock(LockMode::Exclusive).unwrap();
            store_value_with_chunk_size(&store, "account", &value, Some(4)).unwrap();
            store_value_with_chunk_size(&store, "account", &value, Some(4)).unwrap();
        }
        store_value(&store, "account", &value).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), value);
        delete_value(&store, "account").unwrap();
        assert!(store.inner.get_password("account").unwrap().is_none());
        // Outside every operation the lock is free again.
        CredentialLock::acquire(&store.path, LockMode::Exclusive, Duration::ZERO).unwrap();
    }

    #[test]
    fn a_busy_lock_has_its_own_error_code() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let _writer = CredentialLock::acquire(&path, LockMode::Exclusive, Duration::ZERO).unwrap();
        let error = CredentialLock::acquire(&path, LockMode::Shared, Duration::ZERO).unwrap_err();
        assert_eq!(error.metadata(), ("CredentialLockBusy", 0));
    }

    #[test]
    fn an_exclusive_lock_excludes_every_other_holder_until_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join(LOCK_FILE);
        let short = Duration::from_millis(100);

        let writer = CredentialLock::acquire(&path, LockMode::Exclusive, short).unwrap();
        for mode in [LockMode::Exclusive, LockMode::Shared] {
            let error = CredentialLock::acquire(&path, mode, short).unwrap_err();
            assert!(error.to_string().contains("credential lock"), "{error}");
        }
        drop(writer);
        CredentialLock::acquire(&path, LockMode::Exclusive, short).unwrap();
    }

    #[test]
    fn shared_locks_coexist_but_keep_a_writer_out() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let short = Duration::from_millis(100);

        let first = CredentialLock::acquire(&path, LockMode::Shared, short).unwrap();
        let second = CredentialLock::acquire(&path, LockMode::Shared, short).unwrap();
        assert!(CredentialLock::acquire(&path, LockMode::Exclusive, short).is_err());
        drop((first, second));
        CredentialLock::acquire(&path, LockMode::Exclusive, short).unwrap();
    }

    #[test]
    fn a_writer_waits_for_a_reader_that_finishes_in_time() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let reader = CredentialLock::acquire(&path, LockMode::Shared, LOCK_POLL).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(reader);
        });
        CredentialLock::acquire(&path, LockMode::Exclusive, Duration::from_secs(5)).unwrap();
        release.join().unwrap();
    }

    #[test]
    fn legacy_single_entry_remains_readable() {
        let store = MemoryStore::default();
        store.set_password("account", "legacy-json").unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "legacy-json");
    }

    #[test]
    fn chunked_round_trip_uses_raw_bytes() {
        let store = MemoryStore::default();
        let value = "Ünïcödé ✓ 日本語".repeat(20);
        store_value_with_chunk_size(&store, "account", &value, Some(7)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), value);
        assert!(store.keys().len() > 2);
    }

    #[test]
    fn shrinking_a_value_removes_stale_chunks() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(500), Some(32)).unwrap();
        let before = store.keys().len();
        store_value_with_chunk_size(&store, "account", "short", Some(32)).unwrap();
        assert!(store.keys().len() < before);
        assert_eq!(get_value(&store, "account").unwrap(), "short");
    }

    #[test]
    fn incomplete_chunk_set_has_actionable_error() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(200), Some(32)).unwrap();
        store.remove("account:1");
        let error = get_value(&store, "account").unwrap_err().to_string();
        assert!(error.contains("incomplete"));
        assert!(error.contains("entra auth login"));
    }

    #[test]
    fn deletion_sweeps_recorded_chunks_despite_gaps_and_trailing_entries() {
        let store = MemoryStore::default();
        store.set_password("account", r#"{"chunks":3}"#).unwrap();
        for index in [0, 1, 3, 4, 5] {
            store
                .set_secret(&chunk_key("account", 0, index), b"x")
                .unwrap();
        }
        delete_chunks(&store, "account", 0, 0).unwrap();
        assert_eq!(store.keys(), vec!["account"]);
    }

    // An interrupted cleanup can delete the first chunks of a slot and leave
    // later ones. Neither a rewrite nor logout may stop at that gap.
    #[test]
    fn stale_chunks_behind_a_gap_are_removed_by_writes_and_logout() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", "live", Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", "live", Some(32)).unwrap();
        store.set_secret("account:2", b"stale").unwrap();
        store.set_secret("account:3", b"stale").unwrap();

        store_value_with_chunk_size(&store, "account", "next", Some(32)).unwrap();
        assert_eq!(store.keys(), vec!["account", "account:0"]);

        store.set_secret("account:s1:5", b"stale").unwrap();
        delete_all_chunks(&store, "account").unwrap();
        store.delete("account").unwrap();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn rewrites_alternate_slots_and_leave_no_old_chunks() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", &"b".repeat(40), Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "b".repeat(40));
        assert_eq!(
            store.keys(),
            vec!["account", "account:s1:0", "account:s1:1"]
        );
        store_value_with_chunk_size(&store, "account", "c", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "c");
        assert_eq!(store.keys(), vec!["account", "account:0"]);
    }

    #[test]
    fn a_header_from_before_slots_existed_is_read_and_replaced() {
        let store = MemoryStore::default();
        store.set_password("account", r#"{"chunks":2}"#).unwrap();
        store.set_secret("account:0", b"ab").unwrap();
        store.set_secret("account:1", b"cd").unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "abcd");
        store_value_with_chunk_size(&store, "account", "new", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "new");
        assert_eq!(store.keys(), vec!["account", "account:s1:0"]);
    }

    /// Fails every chunk write after the first `allowed`, and every header
    /// write while `fail_header` is set.
    struct FailingStore {
        inner: MemoryStore,
        allowed: std::sync::atomic::AtomicUsize,
        fail_header: std::sync::atomic::AtomicBool,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::default(),
                allowed: std::sync::atomic::AtomicUsize::new(usize::MAX),
                fail_header: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl CredentialStore for FailingStore {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.inner.get_password(key)
        }
        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            if self.fail_header.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(EntraError::message("simulated header write failure"));
            }
            self.inner.set_password(key, value)
        }
        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            use std::sync::atomic::Ordering;
            let remaining = self.allowed.load(Ordering::SeqCst);
            if remaining == 0 {
                return Err(EntraError::message("simulated credential store failure"));
            }
            self.allowed.store(remaining - 1, Ordering::SeqCst);
            self.inner.set_secret(key, value)
        }
        fn delete(&self, key: &str) -> Result<bool> {
            self.inner.delete(key)
        }
    }

    #[test]
    fn a_failed_rewrite_leaves_the_previous_credential_readable() {
        let store = FailingStore::new();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store.allowed.store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store_value_with_chunk_size(&store, "account", &"b".repeat(100), Some(32)).is_err()
        );
        assert_eq!(get_value(&store, "account").unwrap(), "a".repeat(100));

        store
            .allowed
            .store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        store_value_with_chunk_size(&store, "account", "b", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "b");
        assert!(!store
            .inner
            .keys()
            .iter()
            .any(|key| key.starts_with("account:0")));
    }

    #[test]
    fn a_failed_header_write_leaves_a_slot_one_credential_readable() {
        let store = FailingStore::new();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", &"b".repeat(100), Some(32)).unwrap();
        assert!(store.inner.keys().iter().any(|key| key.contains(":s1:")));

        store
            .fail_header
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store_value_with_chunk_size(&store, "account", &"c".repeat(100), Some(32)).is_err()
        );
        assert_eq!(get_value(&store, "account").unwrap(), "b".repeat(100));
    }

    #[test]
    fn logout_removes_chunks_in_both_slots() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store.set_secret("account:s1:0", b"stale").unwrap();
        delete_all_chunks(&store, "account").unwrap();
        store.delete("account").unwrap();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn invalid_chunk_headers_are_bounded() {
        let store = MemoryStore::default();
        store
            .set_password("account", r#"{"chunks":999999}"#)
            .unwrap();
        assert!(get_value(&store, "account")
            .unwrap_err()
            .to_string()
            .contains("invalid chunk count"));
    }

    #[test]
    fn a_new_write_heals_an_invalid_header() {
        let store = MemoryStore::default();
        store
            .set_password("account", r#"{"chunks":999999}"#)
            .unwrap();
        store_value_with_chunk_size(&store, "account", "replacement", Some(4)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "replacement");
    }
}
