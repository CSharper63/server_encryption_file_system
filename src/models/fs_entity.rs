use rocket::log::private::info;
use std::{fs, path::Path};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

use crate::models::database::Database;

use super::data_asset::DataAsset;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FsEntity {
    // must be sent to the client while logged in
    // the root dir will contain top level dirs/files that will each get a key encrpyted with the user master key
    pub uid: String,
    pub path: String,
    pub parent_id: String,
    pub name: DataAsset,
    pub entity_type: String, // file or dir
    pub key: DataAsset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<DataAsset>, // only used for data transfer
}

impl FsEntity {
    pub fn create(&mut self, owner_id: &str) -> bool {
        self.uid = Uuid::new_v4().to_string();

        let path_2_create = if self.path.clone().is_empty() {
            format!(
                "{}/{}",
                Database::get_user_bucket(owner_id),
                &self.name.clone().asset.unwrap()
            )
        } else {
            format!(
                "{}/{}/{}",
                Database::get_user_bucket(owner_id),
                &self.path.clone(),
                &self.name.clone().asset.unwrap()
            )
        };
        if self.entity_type == "dir" {
            // it s a dir
            match fs::create_dir_all(path_2_create) {
                Ok(_) => {
                    // add it to metadata
                    info!("begin dir : {}", self.to_string());

                    Database::add_to_dir_tree(owner_id, self);

                    return true;
                }
                Err(e) => {
                    info!("Error while creating dir : {}", e);
                    return false;
                }
            };
        } else {
            info!("IT IT A FILE: {}", self.name.asset.clone().unwrap());
            info!(
                "Content: {}",
                self.content.clone().unwrap().asset.clone().unwrap()
            );

            let path_2_create = if self.path.clone().is_empty() {
                format!("{}", Database::get_user_bucket(owner_id),)
            } else {
                format!(
                    "{}/{}",
                    Database::get_user_bucket(owner_id),
                    &self.path.clone(),
                )
            };

            if !Path::new(path_2_create.clone().as_str()).exists() {
                fs::create_dir_all(path_2_create.clone().as_str()).unwrap();
            }

            // it s a file
            // create the file
            fs::write(
                format!("{}/{}", path_2_create, self.name.clone().asset.unwrap()),
                bs58::decode(&self.content.clone().unwrap().asset.unwrap())
                    .into_vec()
                    .unwrap(),
            )
            .unwrap();

            // remove content, keep nonce only
            let content_nonce_only = Some(DataAsset {
                asset: None,
                nonce: self.content.clone().unwrap().nonce,
                status: None,
            });

            self.content = content_nonce_only; // remove file content from struct

            Database::add_to_dir_tree(owner_id, self);

            true
        }
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}
