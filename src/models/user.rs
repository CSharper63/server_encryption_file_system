use serde::{Deserialize, Serialize};

use super::data_asset::{DataAsset, Sharing};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub uid: String,
    pub username: String,
    pub clear_salt: String,
    pub master_key: DataAsset,
    pub auth_key: String,
    pub public_key: String,
    pub private_key: DataAsset,
    // contains the file/folder
    pub shared_to_others: Option<Vec<Sharing>>, // uid
    pub shared_to_me: Option<Vec<Sharing>>,
}
