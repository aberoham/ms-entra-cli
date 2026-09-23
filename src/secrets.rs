use serde::{Deserialize, Serialize};

use crate::error::{EntraError, Result};

const SERVICE_NAME: &str = "entra";
const TOKEN_PREFIX: &str = "entra:token:";
#[cfg(target_os = "macos")]
const ITEM_DESCRIPTION: &str = "Microsoft Entra ID access token";
const MAX_CHUNKS: usize = 128;

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
    store_value_with_chunk_size(store, key, value, CHUNK_BYTES)
}

pub fn get_value(store: &dyn CredentialStore, key: &str) -> Result<String> {
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
    }

    impl MemoryStore {
        pub fn remove(&self, key: &str) {
            self.values.lock().unwrap().remove(key);
        }

        pub fn keys(&self) -> Vec<String> {
            self.values.lock().unwrap().keys().cloned().collect()
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
