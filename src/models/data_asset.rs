use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DataState {
    // allow to know if the current processed data are encrypted or not
    Encrypted,
    Decrypted,
}

// must verify that the shared entity is not already shared by parent
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sharing {
    pub key: String,
    pub entity_uid: String, // shared entity
    pub owner_id: String,   // owner that shared the entity
    pub user_id: String,    // User id I share with
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataAsset {
    // can contain encrypted/decrypted data
    pub asset: Option<String>,
    pub nonce: Option<String>,

    #[serde(skip_serializing)]
    pub status: Option<DataState>,
}
