// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac as MacT};
use sha2::Sha256;

use ruma::{
    CanonicalJsonObject, CanonicalJsonValue,
    api::client::backup::{
        EncryptedSessionData,
        EncryptedSessionDataInit,
        EncryptedSessionDataUnsignedInit,
        KeyBackupData,
        KeyBackupDataInit,
    },
    serde::Base64,
};
use vodozemac::Curve25519PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{compat::PkEncryption, decryption::DecodeError};
use crate::{
    olm::InboundGroupSession,
    types::Signatures,
    error::SignatureError,
};

type HmacSha256 = Hmac<Sha256>;

/// An HMAC-SHA-256 key
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct HmacSha256Key(Box<[u8; 32]>);

impl std::fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HmacSha256Key")
         .field(&"*****")
         .finish()
    }
}

impl HmacSha256Key {
    /// Create a new HMAC-SHA-256 key
    pub fn new(value: Box<[u8; 32]>) -> Self {
        Self(value)
    }

    fn make_signable_json(value: &EncryptedSessionData) -> Result<String, SignatureError> {
        let mut json_value = CanonicalJsonObject::from([
            ("ephemeral".to_string(), value.ephemeral.encode().into()),
            ("ciphertext".to_string(), value.ciphertext.encode().into()),
            ("mac".to_string(), value.mac.encode().into()),
        ]);
        for (key, val) in value.other.iter() {
            json_value.insert(key.clone(), CanonicalJsonValue::try_from(val.clone()).map_err(|_| SignatureError::NotAnObject)?);
        }

        let canonical_json: CanonicalJsonValue = json_value.try_into().unwrap();
        Ok(canonical_json.to_string())
    }

    /// Calculate the MAC for an `EncryptedSessionData` and add it to the `signatures`.
    pub fn sign(&self, value: &mut EncryptedSessionData) -> Result<(), SignatureError> {
        let serialized = Self::make_signable_json(value)?;
        let mac = vodozemac::base64_encode(self.calculate_hmac(serialized.as_bytes()).finalize().into_bytes());

        value.unsigned = Some(EncryptedSessionDataUnsignedInit { backup_mac: Some(mac) }.into());
        Ok(())
    }

    fn calculate_hmac(&self, message: &[u8]) -> HmacSha256 {
        let mut hmac = HmacSha256::new_from_slice(self.0.as_ref())
            .expect("We should be able to create a Hmac object from a 32 byte key");
        hmac.update(message);
        hmac
    }

    /// Verify a MAC in an `EncryptedSessionData`
    pub fn verify(&self, value: &EncryptedSessionData) -> Result<(), SignatureError> {
        let serialized = Self::make_signable_json(value)?;

        let mac = value.unsigned.as_ref().and_then(|unsigned| unsigned.backup_mac.as_ref()).ok_or(SignatureError::NoSignatureFound)?;

        let mac = vodozemac::base64_decode(mac).map_err(|_| SignatureError::InvalidSignature)?;

        Ok(
            self.calculate_hmac(serialized.as_bytes())
                .verify_slice(&mac)
                .map_err(|_| SignatureError::InvalidSignature)? // FIXME: should be ::VerificationError
        )
    }
}

#[derive(Debug)]
struct InnerBackupKey {
    key: Curve25519PublicKey,
    mac_key: Option<HmacSha256Key>,
    signatures: Signatures,
    version: Mutex<Option<String>>,
}

/// The public part of a backup key.
#[derive(Clone)]
pub struct MegolmV1BackupKey {
    inner: Arc<InnerBackupKey>,
}

#[cfg(not(tarpaulin_include))]
impl std::fmt::Debug for MegolmV1BackupKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MegolmV1BackupKey")
            .field("key", &self.to_base64())
            .field("version", &self.backup_version())
            .finish()
    }
}

impl MegolmV1BackupKey {
    pub(super) fn new(key: Curve25519PublicKey, mac_key: Option<HmacSha256Key>, version: Option<String>) -> Self {
        Self {
            inner: InnerBackupKey {
                key,
                mac_key,
                signatures: Default::default(),
                version: Mutex::new(version),
            }
            .into(),
        }
    }

    /// Get the full name of the backup algorithm this backup key supports.
    pub fn backup_algorithm(&self) -> &str {
        "m.megolm_backup.v1.curve25519-aes-sha2"
    }

    /// Get all the signatures of this `MegolmV1BackupKey`.
    pub fn signatures(&self) -> Signatures {
        self.inner.signatures.to_owned()
    }

    /// Try to create a new `MegolmV1BackupKey` from a base 64 encoded string.
    pub fn from_base64(public_key: &str) -> Result<Self, DecodeError> {
        let key = Curve25519PublicKey::from_base64(public_key)?;

        let inner =
            InnerBackupKey { key, mac_key: None, signatures: Default::default(), version: Mutex::new(None) };

        Ok(MegolmV1BackupKey { inner: inner.into() })
    }

    /// Convert the [`MegolmV1BackupKey`] to a base 64 encoded string.
    pub fn to_base64(&self) -> String {
        self.inner.key.to_base64()
    }

    /// Get the backup version that this key is used with, if any.
    pub fn backup_version(&self) -> Option<String> {
        self.inner.version.lock().unwrap().clone()
    }

    /// Get the MAC key that is used with the backup key
    pub(crate) fn mac_key(&self) -> Option<&HmacSha256Key> {
        self.inner.mac_key.as_ref()
    }

    /// Set the backup version that this `MegolmV1BackupKey` will be used with.
    ///
    /// The key won't be able to encrypt room keys unless a version has been
    /// set.
    pub fn set_version(&self, version: String) {
        *self.inner.version.lock().unwrap() = Some(version);
    }

    pub(crate) async fn encrypt(&self, session: InboundGroupSession) -> KeyBackupData {
        let pk = PkEncryption::from_key(self.inner.key);

        // The forwarding chains don't mean much, we only care whether we received the
        // session directly from the creator of the session or not.
        let forwarded_count = (session.has_been_imported() as u8).into();
        let first_message_index = session.first_known_index().into();

        // Convert our key to the backup representation.
        let key = session.to_backup().await;

        // The key gets zeroized in `BackedUpRoomKey` but we're creating a copy
        // here that won't, so let's wrap it up in a `Zeroizing` struct.
        let key =
            Zeroizing::new(serde_json::to_vec(&key).expect("Can't serialize exported room key"));

        let message = pk.encrypt(&key);

        let mut session_data = EncryptedSessionDataInit {
            ephemeral: Base64::new(message.ephemeral_key.to_vec()),
            ciphertext: Base64::new(message.ciphertext),
            mac: Base64::new(message.mac.unwrap()),
        }
        .into();
        if let Some(mac_key) = self.mac_key() {
            mac_key.sign(&mut session_data).unwrap();
        };

        KeyBackupDataInit {
            first_message_index,
            forwarded_count,
            // TODO: is this actually used anywhere? seems to be completely
            // useless and requires us to get the Device out of the store?
            // Also should this be checked at the time of the backup or at the
            // time of the room key receival?
            is_verified: false,
            session_data,
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk_test::async_test;
    use ruma::{device_id, room_id, user_id};
    use crate::{
        store::BackupDecryptionKey,
        OlmMachine,
    };

    #[async_test]
    async fn create_mac2() -> Result<(), ()> {
        let decryption_key = BackupDecryptionKey::new().expect("Can't create new recovery key");

        let backup_key = decryption_key.megolm_v1_public_key();

        let olm_machine = OlmMachine::new(user_id!("@alice:localhost"), device_id!("ABCDEFG")).await;
        let inbound = olm_machine.create_inbound_session(room_id!("!room_id:localhost"))
            .await
            .expect("Could not create group session");
        let key_backup_data = backup_key.encrypt(inbound).await;

        let _ = decryption_key
            .decrypt_session_data(key_backup_data.session_data)
            .expect("The backed up key should be decrypted successfully");

        Ok(())
    }
}
