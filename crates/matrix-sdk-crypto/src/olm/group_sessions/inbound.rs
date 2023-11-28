// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fmt,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc,
    },
};

use ruma::{
    events::{room::history_visibility::HistoryVisibility, AnyTimelineEvent},
    serde::Raw,
    DeviceKeyAlgorithm, OwnedRoomId, RoomId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use vodozemac::{
    megolm::{
        DecryptedMessage, DecryptionError, InboundGroupSession as InnerSession,
        InboundGroupSessionPickle, MegolmMessage, SessionConfig, SessionOrdering,
    },
    Curve25519PublicKey, Ed25519PublicKey, PickleError,
};

use super::{
    BackedUpRoomKey, ExportedRoomKey, OutboundGroupSession, SessionCreationError, SessionKey, UnauthenticatedSource
};
use crate::{
    error::{EventError, MegolmResult},
    types::{
        deserialize_curve_key,
        events::{
            forwarded_room_key::{
                ForwardedMegolmV1AesSha2Content, ForwardedMegolmV2AesSha2Content,
                ForwardedRoomKeyContent,
            },
            olm_v1::DecryptedForwardedRoomKeyEvent,
            room::encrypted::{EncryptedEvent, RoomEventEncryptionScheme},
        },
        serialize_curve_key, EventEncryptionAlgorithm, SigningKeys,
    },
};

// TODO add creation times to the inbound group sessions so we can export
// sessions that were created between some time period, this should only be set
// for non-imported sessions.

/// Information about the creator of an inbound group session.
#[derive(Clone)]
pub(crate) struct SessionCreatorInfo {
    /// The Curve25519 identity key of the session creator.
    ///
    /// If the session was received directly from its creator device through an
    /// `m.room_key` event (and therefore, session sender == session creator),
    /// this key equals the Curve25519 device identity key of that device. Since
    /// this key is one of three keys used to establish the Olm session through
    /// which encrypted to-device messages (including `m.room_key`) are sent,
    /// this constitutes a proof that this inbound group session is owned by
    /// that particular Curve25519 key.
    ///
    /// However, if the session was simply forwarded to us in an
    /// `m.forwarded_room_key` event (in which case sender != creator), this key
    /// is just a *claim* made by the session sender of what the actual creator
    /// device is.
    pub curve25519_key: Curve25519PublicKey,

    /// A mapping of DeviceKeyAlgorithm to the public signing keys of the
    /// [`Device`] that sent us the session.
    ///
    /// If the session was received directly from the creator via an
    /// `m.room_key` event, this map is taken from the plaintext value of
    /// the decrypted Olm event, and is a copy of the
    /// [`DecryptedOlmV1Event::keys`] field as defined in the [spec].
    ///
    /// If the session was forwarded to us using an `m.forwarded_room_key`, this
    /// map is a copy of the claimed Ed25519 key from the content of the
    /// event.
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#molmv1curve25519-aes-sha2
    pub signing_keys: Arc<SigningKeys<DeviceKeyAlgorithm>>,
}

/// The source of a key.
///
/// Indicates where we obtained the key from.  The source affects how
/// trustworthy we consider the key and its associated information to be.  If
/// the source is `Direct` or `Backup` with `authenticated: true`, then it is
/// considered trustworthy.  Otherwise, it is not considered trustworthy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeySource {
    /// The key was obtained directly from the session creator via an
    /// `m.room_key` event.
    Direct,
    /// The key was restored from key backup.
    Backup { unauthenticated: Option<UnauthenticatedSource> },
    /// The key was received via an `m.forwarded_room_key` event
    Forward,
    /// The key was imported from a key export.
    OldStyleImport,
}

/// A structure representing an inbound group session.
///
/// Inbound group sessions, also known as "room keys", are used to facilitate
/// the exchange of room messages among a group of participants. The inbound
/// variant of the group session is used to decrypt the room messages.
///
/// This struct wraps the [vodozemac] type of the same name, and adds additional
/// Matrix-specific data to it. Additionally, the wrapper ensures thread-safe
/// access of the vodozemac type.
///
/// [vodozemac]: https://matrix-org.github.io/vodozemac/vodozemac/index.html
#[derive(Clone)]
pub struct InboundGroupSession {
    inner: Arc<Mutex<InnerSession>>,

    /// A copy of [`InnerSession::session_id`] to avoid having to acquire a lock
    /// to get to the sesison ID.
    session_id: Arc<str>,

    /// A copy of [`InnerSession::first_known_index`] to avoid having to acquire
    /// a lock to get to the first known index.
    first_known_index: u32,

    /// Information about the creator of the [`InboundGroupSession`] ("room
    /// key"). The trustworthiness of the information in this field depends
    /// on how the session was received.
    pub(crate) creator_info: SessionCreatorInfo,

    /// The Room this GroupSession belongs to
    pub room_id: OwnedRoomId,

    /// Where we obtained the group session from.
    key_source: KeySource,

    /// The messaging algorithm of this [`InboundGroupSession`] as defined by
    /// the [spec]. Will be one of the `m.megolm.*` algorithms.
    ///
    /// [spec]: https://spec.matrix.org/unstable/client-server-api/#messaging-algorithms
    algorithm: Arc<EventEncryptionAlgorithm>,

    /// The history visibility of the room at the time when the room key was
    /// created.
    history_visibility: Arc<Option<HistoryVisibility>>,

    /// Was this room key backed up to the server.
    backed_up: Arc<AtomicBool>,
}

impl InboundGroupSession {
    /// Create a new inbound group session for the given room.
    ///
    /// These sessions are used to decrypt room messages.
    ///
    /// # Arguments
    ///
    /// * `sender_key` - The public Curve25519 key of the account that
    /// sent us the session.
    ///
    /// * `signing_key` - The public Ed25519 key of the account that
    /// sent us the session.
    ///
    /// * `room_id` - The id of the room that the session is used in.
    ///
    /// * `session_key` - The private session key that is used to decrypt
    /// messages.
    pub fn new(
        sender_key: Curve25519PublicKey,
        signing_key: Ed25519PublicKey,
        room_id: &RoomId,
        session_key: &SessionKey,
        encryption_algorithm: EventEncryptionAlgorithm,
        history_visibility: Option<HistoryVisibility>,
    ) -> Result<Self, SessionCreationError> {
        let config = OutboundGroupSession::session_config(&encryption_algorithm)?;

        let session = InnerSession::new(session_key, config);
        let session_id = session.session_id();
        let first_known_index = session.first_known_index();

        let mut keys = SigningKeys::new();
        keys.insert(DeviceKeyAlgorithm::Ed25519, signing_key.into());

        Ok(InboundGroupSession {
            inner: Arc::new(Mutex::new(session)),
            history_visibility: history_visibility.into(),
            session_id: session_id.into(),
            first_known_index,
            creator_info: SessionCreatorInfo {
                curve25519_key: sender_key,
                signing_keys: keys.into(),
            },
            room_id: room_id.into(),
            key_source: KeySource::Direct,
            algorithm: encryption_algorithm.into(),
            backed_up: AtomicBool::new(false).into(),
        })
    }

    /// Create a InboundGroupSession from an exported version of the group
    /// session.
    ///
    /// Most notably this can be called with an `ExportedRoomKey` from a
    /// previous [`export()`] call.
    ///
    /// [`export()`]: #method.export
    pub fn from_export(exported_session: &ExportedRoomKey) -> Result<Self, SessionCreationError> {
        Self::try_from(exported_session)
    }

    #[allow(dead_code)]
    fn from_backup(
        room_id: &RoomId,
        backup: BackedUpRoomKey,
    ) -> Result<Self, SessionCreationError> {
        // We're using this session only to get the session id, the session
        // config doesn't matter here.
        let session = InnerSession::import(&backup.session_key, SessionConfig::default());
        let session_id = session.session_id();

        let mut res = Self::from_export(&ExportedRoomKey {
            algorithm: backup.algorithm,
            room_id: room_id.to_owned(),
            sender_key: backup.sender_key,
            session_id,
            forwarding_curve25519_key_chain: vec![],
            session_key: backup.session_key,
            sender_claimed_keys: backup.sender_claimed_keys,
        })?;
        res.key_source = KeySource::Backup { unauthenticated: backup.unauthenticated.clone() };
        Ok(res)
    }

    /// Store the group session as a base64 encoded string.
    ///
    /// # Arguments
    ///
    /// * `pickle_mode` - The mode that was used to pickle the group session,
    /// either an unencrypted mode or an encrypted using passphrase.
    pub async fn pickle(&self) -> PickledInboundGroupSession {
        let pickle = self.inner.lock().await.pickle();

        PickledInboundGroupSession {
            pickle,
            sender_key: self.creator_info.curve25519_key,
            signing_key: (*self.creator_info.signing_keys).clone(),
            room_id: self.room_id().to_owned(),
            key_source: self.key_source.clone(),
            backed_up: self.backed_up(),
            history_visibility: self.history_visibility.as_ref().clone(),
            algorithm: (*self.algorithm).to_owned(),
        }
    }

    /// Export this session at the first known message index.
    ///
    /// If only a limited part of this session should be exported use
    /// [`export_at_index()`](#method.export_at_index).
    pub async fn export(&self) -> ExportedRoomKey {
        self.export_at_index(self.first_known_index()).await
    }

    /// Get the sender key that this session was received from.
    pub fn sender_key(&self) -> Curve25519PublicKey {
        self.creator_info.curve25519_key
    }

    /// Has the session been backed up to the server.
    pub fn backed_up(&self) -> bool {
        self.backed_up.load(SeqCst)
    }

    /// Reset the backup state of the inbound group session.
    pub fn reset_backup_state(&self) {
        self.backed_up.store(false, SeqCst)
    }

    /// For testing, allow to manually mark this GroupSession to have been
    /// backed up
    pub fn mark_as_backed_up(&self) {
        self.backed_up.store(true, SeqCst)
    }

    /// Get the map of signing keys this session was received from.
    pub fn signing_keys(&self) -> &SigningKeys<DeviceKeyAlgorithm> {
        &self.creator_info.signing_keys
    }

    /// Export this session at the given message index.
    pub async fn export_at_index(&self, message_index: u32) -> ExportedRoomKey {
        let message_index = std::cmp::max(self.first_known_index(), message_index);

        let session_key =
            self.inner.lock().await.export_at(message_index).expect("Can't export session");

        ExportedRoomKey {
            algorithm: self.algorithm().to_owned(),
            room_id: self.room_id().to_owned(),
            sender_key: self.creator_info.curve25519_key,
            session_id: self.session_id().to_owned(),
            forwarding_curve25519_key_chain: vec![],
            sender_claimed_keys: (*self.creator_info.signing_keys).clone(),
            session_key,
        }
    }

    /// Restore a Session from a previously pickled string.
    ///
    /// Returns the restored group session or a `UnpicklingError` if there
    /// was an error.
    ///
    /// # Arguments
    ///
    /// * `pickle` - The pickled version of the `InboundGroupSession`.
    ///
    /// * `pickle_mode` - The mode that was used to pickle the session, either
    /// an unencrypted mode or an encrypted using passphrase.
    pub fn from_pickle(pickle: PickledInboundGroupSession) -> Result<Self, PickleError> {
        let session: InnerSession = pickle.pickle.into();
        let first_known_index = session.first_known_index();
        let session_id = session.session_id();

        Ok(InboundGroupSession {
            inner: Mutex::new(session).into(),
            session_id: session_id.into(),
            creator_info: SessionCreatorInfo {
                curve25519_key: pickle.sender_key,
                signing_keys: pickle.signing_key.into(),
            },
            history_visibility: pickle.history_visibility.into(),
            first_known_index,
            room_id: (*pickle.room_id).into(),
            backed_up: AtomicBool::from(pickle.backed_up).into(),
            algorithm: pickle.algorithm.into(),
            key_source: pickle.key_source,
        })
    }

    /// The room where this session is used in.
    pub fn room_id(&self) -> &RoomId {
        &self.room_id
    }

    /// Returns the unique identifier for this session.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The algorithm that this inbound group session is using to decrypt
    /// events.
    pub fn algorithm(&self) -> &EventEncryptionAlgorithm {
        &self.algorithm
    }

    /// Get the first message index we know how to decrypt.
    pub fn first_known_index(&self) -> u32 {
        self.first_known_index
    }

    /// Has the session been imported from a file or server-side backup? As
    /// opposed to being directly received as an `m.room_key` event.
    pub fn has_been_imported(&self) -> bool {
        match self.key_source {
            KeySource::Direct => false,
            _ => true,
        }
    }

    /// Where the key came from.
    pub fn key_source(&self) -> &KeySource {
        &self.key_source
    }

    /// Check if the `InboundGroupSession` is better than the given other
    /// `InboundGroupSession`
    pub async fn compare(&self, other: &InboundGroupSession) -> SessionOrdering {
        // If this is the same object the ordering is the same, we can't compare because
        // we would deadlock while trying to acquire the same lock twice.
        if Arc::ptr_eq(&self.inner, &other.inner) {
            SessionOrdering::Equal
        } else if self.sender_key() != other.sender_key()
            || self.signing_keys() != other.signing_keys()
            || self.algorithm() != other.algorithm()
            || self.room_id() != other.room_id()
        {
            SessionOrdering::Unconnected
        } else {
            let mut other = other.inner.lock().await;
            self.inner.lock().await.compare(&mut other)
        }
    }

    /// Decrypt the given ciphertext.
    ///
    /// Returns the decrypted plaintext or an `DecryptionError` if
    /// decryption failed.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that should be decrypted.
    pub(crate) async fn decrypt_helper(
        &self,
        message: &MegolmMessage,
    ) -> Result<DecryptedMessage, DecryptionError> {
        self.inner.lock().await.decrypt(message)
    }

    /// Export the inbound group session into a format that can be uploaded to
    /// the server as a backup.
    pub async fn to_backup(&self) -> BackedUpRoomKey {
        let mut result: BackedUpRoomKey = self.export().await.into();
        result.unauthenticated = match &self.key_source {
            KeySource::Direct => None,
            KeySource::Backup{unauthenticated: src} => src.clone(),
            KeySource::Forward => Some(UnauthenticatedSource::Forwarded),
            KeySource::OldStyleImport => Some(UnauthenticatedSource::Undefined),
        };
        result
    }

    /// Decrypt an event from a room timeline.
    ///
    /// # Arguments
    ///
    /// * `event` - The event that should be decrypted.
    pub async fn decrypt(
        &self,
        event: &EncryptedEvent,
    ) -> MegolmResult<(Raw<AnyTimelineEvent>, u32)> {
        let decrypted = match &event.content.scheme {
            RoomEventEncryptionScheme::MegolmV1AesSha2(c) => {
                self.decrypt_helper(&c.ciphertext).await?
            }
            #[cfg(feature = "experimental-algorithms")]
            RoomEventEncryptionScheme::MegolmV2AesSha2(c) => {
                self.decrypt_helper(&c.ciphertext).await?
            }
            RoomEventEncryptionScheme::Unknown(_) => {
                return Err(EventError::UnsupportedAlgorithm.into());
            }
        };

        let plaintext = String::from_utf8_lossy(&decrypted.plaintext);

        let mut decrypted_value = serde_json::from_str::<Value>(&plaintext)?;
        let decrypted_object = decrypted_value.as_object_mut().ok_or(EventError::NotAnObject)?;

        let server_ts: i64 = event.origin_server_ts.0.into();

        decrypted_object.insert("sender".to_owned(), event.sender.to_string().into());
        decrypted_object.insert("event_id".to_owned(), event.event_id.to_string().into());
        decrypted_object.insert("origin_server_ts".to_owned(), server_ts.into());

        let room_id = decrypted_object
            .get("room_id")
            .and_then(|r| r.as_str().and_then(|r| RoomId::parse(r).ok()));

        // Check that we have a room id and that the event wasn't forwarded from
        // another room.
        if room_id.as_deref() != Some(self.room_id()) {
            return Err(EventError::MismatchedRoom(self.room_id().to_owned(), room_id).into());
        }

        decrypted_object.insert(
            "unsigned".to_owned(),
            serde_json::to_value(&event.unsigned).unwrap_or_default(),
        );

        if let Some(decrypted_content) =
            decrypted_object.get_mut("content").and_then(|c| c.as_object_mut())
        {
            if !decrypted_content.contains_key("m.relates_to") {
                if let Some(relation) = &event.content.relates_to {
                    decrypted_content.insert("m.relates_to".to_owned(), relation.to_owned());
                }
            }
        }

        Ok((
            serde_json::from_value::<Raw<AnyTimelineEvent>>(decrypted_value)?,
            decrypted.message_index,
        ))
    }
}

#[cfg(not(tarpaulin_include))]
impl fmt::Debug for InboundGroupSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundGroupSession").field("session_id", &self.session_id()).finish()
    }
}

impl PartialEq for InboundGroupSession {
    fn eq(&self, other: &Self) -> bool {
        self.session_id() == other.session_id()
    }
}

/// A pickled version of an `InboundGroupSession`.
///
/// Holds all the information that needs to be stored in a database to restore
/// an InboundGroupSession.
#[derive(Deserialize, Serialize)]
#[serde(try_from = "PickledInboundGroupSessionIn")]
#[allow(missing_debug_implementations)]
pub struct PickledInboundGroupSession {
    /// The pickle string holding the InboundGroupSession.
    pub pickle: InboundGroupSessionPickle,
    /// The public Curve25519 key of the account that sent us the session
    #[serde(deserialize_with = "deserialize_curve_key", serialize_with = "serialize_curve_key")]
    pub sender_key: Curve25519PublicKey,
    /// The public ed25519 key of the account that sent us the session.
    pub signing_key: SigningKeys<DeviceKeyAlgorithm>,
    /// The id of the room that the session is used in.
    pub room_id: OwnedRoomId,
    /// Where we obtained the group session from.
    pub key_source: KeySource,
    /// Flag remembering if the session has been backed up.
    #[serde(default)]
    pub backed_up: bool,
    /// History visibility of the room when the session was created.
    pub history_visibility: Option<HistoryVisibility>,
    /// The algorithm of this inbound group session.
    #[serde(default = "default_algorithm")]
    pub algorithm: EventEncryptionAlgorithm,
}

/// Deserialization helper for PickledInboundGroupSession
///
/// Allows migration from older versions of the pickle
/// - if `imported` is set, convert to `key_source`
#[derive(Deserialize, Serialize)]
#[allow(missing_debug_implementations)]
struct PickledInboundGroupSessionIn {
    pub pickle: InboundGroupSessionPickle,
    #[serde(deserialize_with = "deserialize_curve_key", serialize_with = "serialize_curve_key")]
    pub sender_key: Curve25519PublicKey,
    pub signing_key: SigningKeys<DeviceKeyAlgorithm>,
    pub room_id: OwnedRoomId,
    pub imported: Option<bool>,
    pub key_source: Option<KeySource>,
    #[serde(default)]
    pub backed_up: bool,
    pub history_visibility: Option<HistoryVisibility>,
    #[serde(default = "default_algorithm")]
    pub algorithm: EventEncryptionAlgorithm,
}

fn default_algorithm() -> EventEncryptionAlgorithm {
    EventEncryptionAlgorithm::MegolmV1AesSha2
}

impl TryFrom<PickledInboundGroupSessionIn> for PickledInboundGroupSession {
    type Error = String;

    fn try_from(val: PickledInboundGroupSessionIn) -> Result<Self, Self::Error> {
        let key_source = match (val.imported, val.key_source) {
            (Some(false), None) => Ok(KeySource::Direct),
            (Some(true), None) => Ok(KeySource::OldStyleImport),
            (None, Some(key_source)) => Ok(key_source),
            (None, None) => Err("missing field: key_source"),
            (Some(_), Some(_)) => Err("imported and key_source cannot both be provided")
        }?;
        Ok(Self {
            pickle: val.pickle,
            sender_key: val.sender_key,
            signing_key: val.signing_key,
            room_id: val.room_id,
            key_source,
            backed_up: val.backed_up,
            history_visibility: val.history_visibility,
            algorithm: val.algorithm,
        })
    }
}

impl TryFrom<&ExportedRoomKey> for InboundGroupSession {
    type Error = SessionCreationError;

    fn try_from(key: &ExportedRoomKey) -> Result<Self, Self::Error> {
        let config = OutboundGroupSession::session_config(&key.algorithm)?;
        let session = InnerSession::import(&key.session_key, config);
        let first_known_index = session.first_known_index();

        Ok(InboundGroupSession {
            inner: Mutex::new(session).into(),
            session_id: key.session_id.to_owned().into(),
            creator_info: SessionCreatorInfo {
                curve25519_key: key.sender_key,
                signing_keys: key.sender_claimed_keys.to_owned().into(),
            },
            history_visibility: None.into(),
            first_known_index,
            room_id: key.room_id.to_owned(),
            key_source: KeySource::OldStyleImport,
            algorithm: key.algorithm.to_owned().into(),
            backed_up: AtomicBool::from(false).into(),
        })
    }
}

impl From<&ForwardedMegolmV1AesSha2Content> for InboundGroupSession {
    fn from(value: &ForwardedMegolmV1AesSha2Content) -> Self {
        let session = InnerSession::import(&value.session_key, SessionConfig::version_1());
        let session_id = session.session_id().into();
        let first_known_index = session.first_known_index();

        InboundGroupSession {
            inner: Mutex::new(session).into(),
            session_id,
            creator_info: SessionCreatorInfo {
                curve25519_key: value.claimed_sender_key,
                signing_keys: SigningKeys::from([(
                    DeviceKeyAlgorithm::Ed25519,
                    value.claimed_ed25519_key.into(),
                )])
                .into(),
            },
            history_visibility: None.into(),
            first_known_index,
            room_id: value.room_id.to_owned(),
            key_source: KeySource::Forward,
            algorithm: EventEncryptionAlgorithm::MegolmV1AesSha2.into(),
            backed_up: AtomicBool::from(false).into(),
        }
    }
}

impl From<&ForwardedMegolmV2AesSha2Content> for InboundGroupSession {
    fn from(value: &ForwardedMegolmV2AesSha2Content) -> Self {
        let session = InnerSession::import(&value.session_key, SessionConfig::version_2());
        let session_id = session.session_id().into();
        let first_known_index = session.first_known_index();

        InboundGroupSession {
            inner: Mutex::new(session).into(),
            session_id,
            creator_info: SessionCreatorInfo {
                curve25519_key: value.claimed_sender_key,
                signing_keys: value.claimed_signing_keys.to_owned().into(),
            },
            history_visibility: None.into(),
            first_known_index,
            room_id: value.room_id.to_owned(),
            key_source: KeySource::Forward,
            algorithm: EventEncryptionAlgorithm::MegolmV1AesSha2.into(),
            backed_up: AtomicBool::from(false).into(),
        }
    }
}

impl TryFrom<&DecryptedForwardedRoomKeyEvent> for InboundGroupSession {
    type Error = SessionCreationError;

    fn try_from(value: &DecryptedForwardedRoomKeyEvent) -> Result<Self, Self::Error> {
        match &value.content {
            ForwardedRoomKeyContent::MegolmV1AesSha2(c) => Ok(Self::from(c.deref())),
            #[cfg(feature = "experimental-algorithms")]
            ForwardedRoomKeyContent::MegolmV2AesSha2(c) => Ok(Self::from(c.deref())),
            ForwardedRoomKeyContent::Unknown(c) => {
                Err(SessionCreationError::Algorithm(c.algorithm.to_owned()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk_test::async_test;
    use ruma::{device_id, room_id, user_id, DeviceId, UserId};
    use vodozemac::{megolm::SessionOrdering, Curve25519PublicKey};

    use crate::{olm::InboundGroupSession, Account};

    fn alice_id() -> &'static UserId {
        user_id!("@alice:example.org")
    }

    fn alice_device_id() -> &'static DeviceId {
        device_id!("ALICEDEVICE")
    }

    #[async_test]
    async fn inbound_group_session_serialization() {
        let pickle = r#"
        {
            "pickle": {
                "initial_ratchet": {
                    "inner": [ 124, 251, 213, 204, 108, 247, 54, 7, 179, 162, 15, 107, 154, 215,
                               220, 46, 123, 113, 120, 162, 225, 246, 237, 203, 125, 102, 190, 212,
                               229, 195, 136, 185, 26, 31, 77, 140, 144, 181, 152, 177, 46, 105,
                               202, 6, 53, 158, 157, 170, 31, 155, 130, 87, 214, 110, 143, 55, 68,
                               138, 41, 35, 242, 230, 194, 15, 16, 145, 116, 94, 89, 35, 79, 145,
                               245, 117, 204, 173, 166, 178, 49, 131, 143, 61, 61, 15, 211, 167, 17,
                               2, 79, 110, 149, 200, 223, 23, 185, 200, 29, 64, 55, 39, 147, 167,
                               205, 224, 159, 101, 218, 249, 203, 30, 175, 174, 48, 252, 40, 131,
                               52, 135, 91, 57, 211, 96, 105, 58, 55, 68, 250, 24 ],
                    "counter": 0
                },
                "signing_key": [ 93, 185, 171, 61, 173, 100, 51, 9, 157, 180, 214, 39, 131, 80, 118,
                                 130, 199, 232, 163, 197, 45, 23, 227, 100, 151, 59, 19, 102, 38,
                                 149, 43, 38 ],
                "signing_key_verified": true,
                "config": {
                  "version": "V1"
                }
            },
            "sender_key": "AmM1DvVJarsNNXVuX7OarzfT481N37GtDwvDVF0RcR8",
            "signing_key": {
                "ed25519": "wTRTdz4rn4EY+68cKPzpMdQ6RAlg7T8cbTmEjaXuUww"
            },
            "room_id": "!test:localhost",
            "forwarding_chains": ["tb6kQKjk+SJl2KnfQ0lKVOZl6gDFMcsb9HcUP9k/4hc"],
            "key_source": "Direct",
            "backed_up": false,
            "history_visibility": "shared",
            "algorithm": "m.megolm.v1.aes-sha2"
        }
        "#;

        let deserialized = serde_json::from_str(pickle).unwrap();

        let unpickled = InboundGroupSession::from_pickle(deserialized).unwrap();

        assert_eq!(unpickled.session_id(), "XbmrPa1kMwmdtNYng1B2gsfoo8UtF+NklzsTZiaVKyY");
    }

    #[async_test]
    async fn inbound_group_session_migration() {
        let pickle = r#"
        {
            "pickle": {
                "initial_ratchet": {
                    "inner": [ 124, 251, 213, 204, 108, 247, 54, 7, 179, 162, 15, 107, 154, 215,
                               220, 46, 123, 113, 120, 162, 225, 246, 237, 203, 125, 102, 190, 212,
                               229, 195, 136, 185, 26, 31, 77, 140, 144, 181, 152, 177, 46, 105,
                               202, 6, 53, 158, 157, 170, 31, 155, 130, 87, 214, 110, 143, 55, 68,
                               138, 41, 35, 242, 230, 194, 15, 16, 145, 116, 94, 89, 35, 79, 145,
                               245, 117, 204, 173, 166, 178, 49, 131, 143, 61, 61, 15, 211, 167, 17,
                               2, 79, 110, 149, 200, 223, 23, 185, 200, 29, 64, 55, 39, 147, 167,
                               205, 224, 159, 101, 218, 249, 203, 30, 175, 174, 48, 252, 40, 131,
                               52, 135, 91, 57, 211, 96, 105, 58, 55, 68, 250, 24 ],
                    "counter": 0
                },
                "signing_key": [ 93, 185, 171, 61, 173, 100, 51, 9, 157, 180, 214, 39, 131, 80, 118,
                                 130, 199, 232, 163, 197, 45, 23, 227, 100, 151, 59, 19, 102, 38,
                                 149, 43, 38 ],
                "signing_key_verified": true,
                "config": {
                  "version": "V1"
                }
            },
            "sender_key": "AmM1DvVJarsNNXVuX7OarzfT481N37GtDwvDVF0RcR8",
            "signing_key": {
                "ed25519": "wTRTdz4rn4EY+68cKPzpMdQ6RAlg7T8cbTmEjaXuUww"
            },
            "room_id": "!test:localhost",
            "forwarding_chains": ["tb6kQKjk+SJl2KnfQ0lKVOZl6gDFMcsb9HcUP9k/4hc"],
            "imported": true,
            "backed_up": false,
            "history_visibility": "shared",
            "algorithm": "m.megolm.v1.aes-sha2"
        }
        "#;

        let deserialized = serde_json::from_str(pickle).unwrap();

        let unpickled = InboundGroupSession::from_pickle(deserialized).unwrap();

        assert_eq!(unpickled.session_id(), "XbmrPa1kMwmdtNYng1B2gsfoo8UtF+NklzsTZiaVKyY");
        assert!(unpickled.has_been_imported());

        let pickle = r#"
        {
            "pickle": {
                "initial_ratchet": {
                    "inner": [ 124, 251, 213, 204, 108, 247, 54, 7, 179, 162, 15, 107, 154, 215,
                               220, 46, 123, 113, 120, 162, 225, 246, 237, 203, 125, 102, 190, 212,
                               229, 195, 136, 185, 26, 31, 77, 140, 144, 181, 152, 177, 46, 105,
                               202, 6, 53, 158, 157, 170, 31, 155, 130, 87, 214, 110, 143, 55, 68,
                               138, 41, 35, 242, 230, 194, 15, 16, 145, 116, 94, 89, 35, 79, 145,
                               245, 117, 204, 173, 166, 178, 49, 131, 143, 61, 61, 15, 211, 167, 17,
                               2, 79, 110, 149, 200, 223, 23, 185, 200, 29, 64, 55, 39, 147, 167,
                               205, 224, 159, 101, 218, 249, 203, 30, 175, 174, 48, 252, 40, 131,
                               52, 135, 91, 57, 211, 96, 105, 58, 55, 68, 250, 24 ],
                    "counter": 0
                },
                "signing_key": [ 93, 185, 171, 61, 173, 100, 51, 9, 157, 180, 214, 39, 131, 80, 118,
                                 130, 199, 232, 163, 197, 45, 23, 227, 100, 151, 59, 19, 102, 38,
                                 149, 43, 38 ],
                "signing_key_verified": true,
                "config": {
                  "version": "V1"
                }
            },
            "sender_key": "AmM1DvVJarsNNXVuX7OarzfT481N37GtDwvDVF0RcR8",
            "signing_key": {
                "ed25519": "wTRTdz4rn4EY+68cKPzpMdQ6RAlg7T8cbTmEjaXuUww"
            },
            "room_id": "!test:localhost",
            "forwarding_chains": ["tb6kQKjk+SJl2KnfQ0lKVOZl6gDFMcsb9HcUP9k/4hc"],
            "imported": false,
            "backed_up": false,
            "history_visibility": "shared",
            "algorithm": "m.megolm.v1.aes-sha2"
        }
        "#;

        let deserialized = serde_json::from_str(pickle).unwrap();

        let unpickled = InboundGroupSession::from_pickle(deserialized).unwrap();

        assert_eq!(unpickled.session_id(), "XbmrPa1kMwmdtNYng1B2gsfoo8UtF+NklzsTZiaVKyY");
        assert!(!unpickled.has_been_imported());
    }

    #[async_test]
    async fn session_comparison() {
        let alice = Account::with_device_id(alice_id(), alice_device_id());
        let room_id = room_id!("!test:localhost");

        let (_, inbound) = alice.create_group_session_pair_with_defaults(room_id).await;

        let worse = InboundGroupSession::from_export(&inbound.export_at_index(10).await).unwrap();
        let mut copy = InboundGroupSession::from_pickle(inbound.pickle().await).unwrap();

        assert_eq!(inbound.compare(&worse).await, SessionOrdering::Better);
        assert_eq!(worse.compare(&inbound).await, SessionOrdering::Worse);
        assert_eq!(inbound.compare(&inbound).await, SessionOrdering::Equal);
        assert_eq!(inbound.compare(&copy).await, SessionOrdering::Equal);

        copy.creator_info.curve25519_key =
            Curve25519PublicKey::from_base64("XbmrPa1kMwmdtNYng1B2gsfoo8UtF+NklzsTZiaVKyY")
                .unwrap();

        assert_eq!(inbound.compare(&copy).await, SessionOrdering::Unconnected);
    }
}
