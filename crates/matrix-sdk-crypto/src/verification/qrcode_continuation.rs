// Copyright 2026 Element Creations Ltd.
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

// TODO: rename this as "reciprocate v2", remove qr code-specific things, since
// it can use different methods

use as_variant::as_variant;
use eyeball::{ObservableWriteGuard, SharedObservable};
use ruma::{
    DeviceId, RoomId, TransactionId, UserId,
    events::{
        AnyMessageLikeEventContent,
        key::verification::{accept, cancel::CancelCode, start},
        relation::Reference,
    },
};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey, SharedSecret};

use super::{
    CancelInfo, Cancelled, FlowId, IdentitiesBeingVerified, VerificationResult,
    VerificationStore,
    event_enums::{CancelContent, DoneContent, OutgoingContent, OwnedStartContent, StartContent},
    requests::RequestHandle,
};
use crate::{
    CryptoStoreError, DeviceData, UserIdentityData, OwnUserIdentityData,
    types::{MasterPubkey, requests::{OutgoingVerificationRequest, RoomMessageRequest, ToDeviceRequest}},
};

const METHOD_NAME: &'static str = "io.element.qr_code.continuation.v1";

/// Data to be encoded in the Qr Code
pub struct QrCodeData {
    pub ephemeral_key: Curve25519PublicKey,
    pub master_signing_key: MasterPubkey,
}

/// Private state of the QR code displayer
#[derive(Clone)]
pub struct QrCodeState {
    pub ephemeral_key: Curve25519SecretKey
}

impl QrCodeState {
    pub async fn create(identity: &OwnUserIdentityData) -> Result<(QrCodeData, QrCodeState), String>{
        let ephemeral_key = Curve25519SecretKey::new();
        Ok((QrCodeData {
            ephemeral_key: From::from(&ephemeral_key),
            master_signing_key: identity.master_key().clone(),
        }, QrCodeState {
            ephemeral_key,
        }))
    }
}

impl std::fmt::Debug for QrCodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrCodeState")
            .finish()
    }
}

// TODO: this and the next struct should actually be defined within ruma::events::key::verification::{start, accept}
#[derive(Debug)]
pub struct StartEvent {
    // method: io.element.qr_code.continuation
    ephemeral_key: Curve25519PublicKey,
    master_signing_key: MasterPubkey,
    // the text "MATRIX_QR_CODE_VERIFICATION_CONTINUATION_INITIATE" encrypted,
    // with the ephemeral key and MSK as additional data
    ciphertext: String
}

impl TryFrom<&start::StartMethod> for StartEvent {
    type Error = String;
    fn try_from(start: &start::StartMethod) -> Result<Self, Self::Error> {
        let start::StartMethod::_Custom(content) = start else {
            return Err("Wrong method".to_string());
        };
        if content.method != METHOD_NAME {
            return Err("Wrong method".to_string());
        }
        let Some(ephemeral_key) = content.data.get("ephemeral_key") else {
            return Err("Missing ephemeral key".to_string());
        };
        let Ok(ephemeral_key) = serde_json::from_value::<Curve25519PublicKey>(ephemeral_key.clone()) else {
            return Err("Invalid ephemeral key".to_string());
        };
        let Some(master_signing_key) = content.data.get("master_signing_key") else {
            return Err("Missing master signing key".to_string());
        };
        let Ok(master_signing_key) = serde_json::from_value::<MasterPubkey>(master_signing_key.clone()) else {
            return Err("Invalid master signing key".to_string());
        };
        let Some(ciphertext) = content.data.get("ciphertext") else {
            return Err("Missing ciphertext".to_string());
        };
        let Ok(ciphertext) = serde_json::from_value::<String>(ciphertext.clone()) else {
            return Err("Invalid string".to_string());
        };
        Ok(Self {
            ephemeral_key,
            master_signing_key,
            ciphertext,
        })
    }
}

impl TryFrom<StartEvent> for start::StartMethod {
    type Error = serde_json::Error;
    fn try_from(start: StartEvent) -> Result<Self, Self::Error> {
        let mut data = std::collections::BTreeMap::new();
        data.insert("ephemeral_key".to_string(), serde_json::to_value(&start.ephemeral_key)?);
        data.insert("master_signing_key".to_string(), serde_json::to_value(&start.master_signing_key)?);
        data.insert("ciphertext".to_string(), serde_json::to_value(&start.ciphertext)?);
        Ok(Self::_Custom(start::_CustomContent {
            method: METHOD_NAME.to_string(),
            data
        }))
    }
}

#[derive(Debug)]
pub struct AcceptEvent {
    // the text "MATRIX_QR_CODE_VERIFICATION_CONTINUATION_OK" encrypted
    ciphertext: String
}

impl TryFrom<accept::AcceptMethod> for AcceptEvent {
    type Error = String;
    fn try_from(accept: accept::AcceptMethod) -> Result<Self, Self::Error> {
        let accept::AcceptMethod::_Custom(content) = accept else {
            return Err("Wrong method".to_string());
        };
        let Some(ciphertext) = content.data.get("ciphertext") else {
            return Err("Missing ciphertext".to_string());
        };
        let Ok(ciphertext) = serde_json::from_value::<String>(ciphertext.clone()) else {
            return Err("Invalid string".to_string());
        };
        Ok(Self {
            ciphertext,
        })
    }
}

impl TryFrom<AcceptEvent> for accept::AcceptMethod {
    type Error = serde_json::Error;
    fn try_from(accept: AcceptEvent) -> Result<Self, Self::Error> {
        let mut data = std::collections::BTreeMap::new();
        data.insert("ciphertext".to_string(), serde_json::to_value(&accept.ciphertext)?);
        Ok(Self::_Custom(accept::_CustomContent {
            method: METHOD_NAME.to_string(),
            data
        }))
    }
}

//      Scanner                    Displayer
//                           [generates ephemeral key]
//   [scans QR code]         [displays QR code]
//   [creates DM]
//   [check MSK and sign]
//     --- m.key.verification.request --->
//                           [auto-accept]
//     <--- m.key.verification.ready ---
//   [generates ephemeral key]
//   [calculates secret]
//   [encrypts check string]
//      --- m.key.verification.start --->
//                           [decrypt and check]
//                           [check MSK]
//                           [calculates secret]
//                           [encrypts check string]
//      <-- m.key.verification.accept ---
//   [decrypt and check]
//      --- m.key.verification.done --->
//   [displays code]         [prompts for code]
//                           [sign MSK]
//      <-- m.key.verification.done ---

enum State {
    /// We have received the other device's details (from the
    /// `m.key.verification.request` or `m.key.verification.ready`)
    Created {
        ephemeral_key: Curve25519SecretKey,
    },

    /// The QR code scanner has sent the `m.key.verification.start` message, which
    /// includes their public ephemeral key and their master signing key
    Started {
        shared_secret: SharedSecret,
        master_signing_key: MasterPubkey,
    },

    /// The QR code displayer has replied, confirming the shared secret.
    /// The 2-digit confirmation code may be displayed/entered.
    SharedSecretConfirmed {
        confirmation_code: String,
        master_signing_key: MasterPubkey,
    },

    Done,

    Cancelled
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Created { .. } =>
                f.debug_struct("State::Created")
                .finish(),
            State::Started {
                master_signing_key,
                ..
            } =>
                f.debug_struct("State::Started")
                .field("master_signing_key", master_signing_key)
                .finish(),
            State::SharedSecretConfirmed {
                confirmation_code,
                master_signing_key,
            } =>
                f.debug_struct("State::SharedSecretConfirmed")
                .field("confirmation_code", confirmation_code)
                .field("master_signing_key", master_signing_key)
                .finish(),
            State::Done =>
                f.debug_struct("State::Done")
                .finish(),
            State::Cancelled =>
                f.debug_struct("State::Cancelled")
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct QrContinuationVerification {
    flow_id: FlowId,
    state: SharedObservable<State>,
    identities: IdentitiesBeingVerified,
    request_handle: RequestHandle,
    we_started: bool,
}

impl std::fmt::Debug for QrContinuationVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrContinuationVerification")
            .field("flow_id", &self.flow_id)
            //.field("inner", &self.inner)
            .field("state", &self.state)
            .finish()
    }
}

impl QrContinuationVerification {
    /// Get our own user id.
    pub fn user_id(&self) -> &UserId {
        self.identities.user_id()
    }

    /// Get the user id of the other user that is participating in this
    /// verification flow.
    pub fn other_user_id(&self) -> &UserId {
        self.identities.other_user_id()
    }

    /// Get the device ID of the other side.
    pub fn other_device_id(&self) -> &DeviceId {
        self.identities.other_device_id()
    }

    /// Get the device of the other user.
    pub fn other_device(&self) -> &DeviceData {
        self.identities.other_device()
    }

    /// Did we initiate the verification request
    pub fn we_started(&self) -> bool {
        self.we_started
    }

    /// Has the verification flow completed.
    pub fn is_done(&self) -> bool {
        matches!(*self.state.read(), State::Done)
    }

    /// Has the verification flow been cancelled.
    pub fn is_cancelled(&self) -> bool {
        matches!(*self.state.read(), State::Cancelled)
    }

    /// Is this a verification that is verifying one of our own devices
    pub fn is_self_verification(&self) -> bool {
        false
    }

    /// Get the unique ID that identifies this QR code verification flow.
    pub fn flow_id(&self) -> &FlowId {
        &self.flow_id
    }

    /// Get the room id if the verification is happening inside a room.
    pub fn room_id(&self) -> Option<&RoomId> {
        match self.flow_id() {
            FlowId::ToDevice(_) => None,
            FlowId::InRoom(r, _) => Some(r),
        }
    }

    /// Cancel the verification flow.
    pub fn cancel(&self) -> Option<OutgoingVerificationRequest> {
        self.cancel_with_code(CancelCode::User)
    }

    /// Cancel the verification.
    ///
    /// This cancels the verification with given `CancelCode`.
    ///
    /// **Note**: This method should generally not be used, the [`cancel()`]
    /// method should be preferred. The SDK will automatically cancel with the
    /// appropriate cancel code, user initiated cancellations should only cancel
    /// with the `CancelCode::User`
    ///
    /// Returns None if the object is already in a canceled state,
    /// otherwise it returns a request that needs to be sent out.
    ///
    /// [`cancel()`]: #method.cancel
    pub fn cancel_with_code(&self, code: CancelCode) -> Option<OutgoingVerificationRequest> {
        let mut state = self.state.write();

        let content = Cancelled::new(true, code).as_content(self.flow_id());

        match &*state {
            State::Created{..}
            | State::Started{..}
            | State::SharedSecretConfirmed{..}
            | State::Done => {
                ObservableWriteGuard::set(&mut state, State::Cancelled);
                Some(self.content_to_request(content))
            }
            State::Cancelled => None,
        }
    }

    fn content_to_request(&self, content: OutgoingContent) -> OutgoingVerificationRequest {
        match content {
            OutgoingContent::Room(room_id, content) => {
                RoomMessageRequest { room_id, txn_id: TransactionId::new(), content }.into()
            }
            OutgoingContent::ToDevice(c) => ToDeviceRequest::with_id(
                self.identities.other_user_id(),
                self.identities.other_device_id().to_owned(),
                &c,
                TransactionId::new(),
            )
            .into(),
        }
    }

    pub async fn create_from_qr_code(
        flow_id: FlowId,
        identities: IdentitiesBeingVerified,
        request_handle: RequestHandle,
        data: QrCodeData,
    ) -> Result<(Self, OutgoingVerificationRequest), String> {
        let our_secret_key = Curve25519SecretKey::new();
        let our_public_key: Curve25519PublicKey = (&our_secret_key).into();
        let shared_secret = our_secret_key.diffie_hellman(&data.ephemeral_key);
        let state = State::Started {
            shared_secret,
            master_signing_key: data.master_signing_key,
        };

        let FlowId::InRoom(room_id, event_id) = flow_id.clone() else {
            return Err("Must be in-room verification".to_string());
        };
        let method = (StartEvent {
            ephemeral_key: our_public_key,
            master_signing_key: identities.private_identity.master_public_key().await.unwrap(),
            // TODO:
            ciphertext: "encrypted MATRIX_QR_CODE_VERIFICATION_CONTINUATION_INITIATE".to_string()
        }).try_into().unwrap();

        let content = AnyMessageLikeEventContent::KeyVerificationStart(start::KeyVerificationStartEventContent::new(identities.store.account.device_id.clone(), method, Reference::new(event_id)));
        let request = RoomMessageRequest {
            room_id: room_id,
            txn_id: TransactionId::new(),
            content: content.into(),
        };

        Ok((Self {
            flow_id,
            state: SharedObservable::new(state),
            identities,
            request_handle,
            we_started: true
        }, request.into()))
    }

    // TODO: create_from_qr_state function

    pub(crate) fn receive_start(
        &self,
        content: &StartContent<'_>,
    ) -> Option<OutgoingVerificationRequest> {
        if self.we_started {
            return None
        }
        let Ok(content) = StartEvent::try_from(content.method()) else {
            return None
        };
        let FlowId::InRoom(room_id, event_id) = self.flow_id.clone() else {
            return None
        };

        let mut state = self.state.write();

        match &*state {
            State::Created{ ephemeral_key } => {
                let shared_secret = ephemeral_key.diffie_hellman(&content.ephemeral_key);
                let new_state = State::SharedSecretConfirmed {
                    confirmation_code: calculate_confirmation_code(&shared_secret),
                    master_signing_key: content.master_signing_key.clone()
                };
                ObservableWriteGuard::set(&mut state, new_state);

                let method = AcceptEvent {
                    // TODO:
                    ciphertext: "encrypted MATRIX_QR_CODE_VERIFICATION_CONTINUATION_OK".to_string()
                };
                let content = AnyMessageLikeEventContent::KeyVerificationAccept(accept::KeyVerificationAcceptEventContent::new(
                    method.try_into().unwrap(),
                    Reference::new(event_id)
                ));
                // FIXME:
                Some(RoomMessageRequest {
                    room_id,
                    txn_id: TransactionId::new(),
                    content: content.into(),
                }.into())
            },
            _ => None,
        }
    }

    // TODO: receive_ready function

    // TODO: receive_done function
}

fn calculate_confirmation_code(secret: &SharedSecret) -> String {
    // FIXME: do the correct calculation
    let number =(secret.as_bytes()[0] % 90) + 10;
    format!("{}", number)
}
