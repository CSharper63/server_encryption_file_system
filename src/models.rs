use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    ops::Deref,
    path::Path,
};

use jsonwebtoken::{
    decode, encode, errors::Error, get_current_timestamp, Algorithm, DecodingKey, EncodingKey,
    Header, Validation,
};

use rocket::log::private::info;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use uuid::Uuid;

const SERVER_ROOT: &str = "vault";
const USERS_DB: &str = "users.json";
const USERS_DIR: &str = "users";
// vault/users/USER_ID/metadata.json/
// vault/users/USER_ID/data/CIPHER_DIR

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DataStatus {
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
    pub status: Option<DataStatus>,
}

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyMaterial {
    pub public_key: String,
    pub owner_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RootTree {
    #[serde(default)]
    pub elements: Option<Vec<FsEntity>>, // contains Dir or Files
}

impl RootTree {
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}

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

        /*         info!("{}", path_2_create.clone());
         */
        if self.entity_type == "dir" {
            // it s a dir
            match fs::create_dir_all(path_2_create) {
                Ok(_) => {
                    // add it to metadata
                    info!("begin dir : {}", self.to_string());

                    // djashdjkashd/akjdhsajkd/dasjbdasjkdh

                    Database::add_to_dir_tree(owner_id, self);
                    /*
                    let file = OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(Database::get_user_metadata_path(owner_id))
                        .unwrap();

                    let mut writer = BufWriter::new(file);
                    serde_json::to_writer(&mut writer, &tree).unwrap(); */

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

#[derive(Debug, Deserialize, Serialize)]
pub struct Database {
    pub users: Vec<User>,
}

/// Database representation: will handle all possible action the end user.
/// This function are called through an API
impl Database {
    fn get_users_db_path() -> String {
        format!("{}/{}", SERVER_ROOT, USERS_DB)
    }

    pub fn get_user_metadata_path(uid: &str) -> String {
        format!(
            "{}/{}/{}/{}",
            SERVER_ROOT,
            USERS_DIR,
            uid,
            format!("{}.json", uid)
        )
    }

    fn get_user_bucket(uid: &str) -> String {
        format!("{}/{}/{}/bucket", SERVER_ROOT, USERS_DIR, uid)
    }

    fn get_all_users() -> Result<Database, Box<dyn std::error::Error>> {
        Self::create_db_if_does_n_exist();
        let file_path = Database::get_users_db_path();
        let file_content = std::fs::read_to_string(&file_path)?;

        let database: Database = serde_json::from_str(&file_content)?;

        Ok(database)
    }

    pub fn update_tree(uid: &str, root: &RootTree) {
        let root_str = serde_json::to_string(root).unwrap();
        fs::write(Database::get_user_metadata_path(uid), root_str.as_bytes())
            .expect("Failed to update user root metadata")
    }

    pub fn add_to_dir_tree(owner_id: &str, element: &FsEntity) -> Option<String> {
        match Database::get_root_tree(owner_id) {
            Some(mut root) => {
                if let Some(elements) = &mut root.elements {
                    elements.push(element.clone());
                }

                let root_str = serde_json::to_string(&root).unwrap();
                fs::write(
                    Database::get_user_metadata_path(owner_id),
                    root_str.as_bytes(),
                )
                .expect("Failed to update user root metadata");
                return Some(String::from("Element successfully added to tree"));
            }
            None => None,
        }
    }

    pub fn get_elem_from_tree(owner_id: &str, element_id: &str) -> Option<FsEntity> {
        match Database::get_root_tree(owner_id) {
            Some(root) => {
                for e in root.elements.unwrap().iter() {
                    if e.uid == element_id {
                        return Some(e.clone());
                    }
                }
                return None;
            }
            None => return None,
        }
    }

    pub fn get_children(owner_id: &str, parent_id: &str) -> Option<Vec<FsEntity>> {
        match Database::get_root_tree(owner_id) {
            Some(root) => {
                let mut all_children: Vec<FsEntity> = Vec::default();
                for e in root.elements.unwrap().iter() {
                    if e.parent_id == parent_id {
                        info!("We found something intersting");
                        all_children.push(e.clone());
                    }
                }
                return Some(all_children);
            }
            None => return None,
        }
    }

    fn create_db_if_does_n_exist() {
        let server_root_path = Path::new(SERVER_ROOT);

        if !server_root_path.exists() {
            fs::create_dir_all(server_root_path).expect("Failed to create server root directory");
        }

        let file_path = Database::get_users_db_path();

        if !Path::new(&file_path).exists() {
            let initial_db = Database { users: Vec::new() };
            let initial_db_json = serde_json::to_string(&initial_db).unwrap();

            fs::write(&file_path, initial_db_json).expect("Failed to create users database");
        }
    }

    pub fn init_root_tree(uid: &str) {
        // by default three is no content in the root dir
        let root_tree = RootTree {
            elements: Some(Vec::default()),
        };

        let root_str = serde_json::to_string(&root_tree).unwrap();

        // write metadata to User space
        fs::write(Database::get_user_metadata_path(uid), root_str.as_bytes())
            .expect("Failed to create user root metadata");
    }

    pub fn get_root_tree(uid: &str) -> Option<RootTree> {
        let file_content = std::fs::read_to_string(&Database::get_user_metadata_path(uid)).unwrap();

        let _: RootTree = match serde_json::from_str(&file_content) {
            Ok(root_tree) => return Some(root_tree),
            Err(_) => return None,
        };
    }
    pub fn share(shares: &Sharing) -> Option<String> {
        // get the target and the owner
        let target_user = Database::get_user_by_id(&shares.user_id);
        let owner_user = Database::get_user_by_id(&shares.owner_id);
        let mut target_updated = false;
        let mut owner_updated = false;
        if let (Some(mut target), Some(mut owner)) = (target_user, owner_user) {
            // Initialize vectors if they are None
            target.shared_to_me.get_or_insert_with(Vec::new);
            owner.shared_to_others.get_or_insert_with(Vec::new);

            let target_shared_to_me = target.shared_to_me.as_mut().unwrap();
            let owner_shared_to_others = owner.shared_to_others.as_mut().unwrap();

            // Check and add share to target user if not exists
            if !target_shared_to_me
                .iter()
                .any(|existing_share| existing_share.entity_uid == shares.entity_uid)
            {
                target_shared_to_me.push(shares.clone());
                target_updated = Database::update_user(&target).is_ok();
            }

            // Check and add share to owner user if not exists
            if !owner_shared_to_others
                .iter()
                .any(|existing_share| existing_share.entity_uid == shares.entity_uid)
            {
                owner_shared_to_others.push(shares.clone());
                owner_updated = Database::update_user(&owner).is_ok();
            }

            if target_updated && owner_updated {
                Some("Share successfully".to_string())
            } else {
                None
            };
        } else {
            return None;
        }

        Some("Share added successfully".to_string())
    }

    pub fn revoke_share(share_id: &str, user_id: &str, owner_id: &str) -> Result<(), String> {
        let mut target_user = Database::get_user_by_id(user_id);
        let mut owner_user = Database::get_user_by_id(owner_id);

        // Check if both users are found
        if let (Some(target), Some(owner)) = (&mut target_user, &mut owner_user) {
            // Remove the share from target user's shared_to_me list
            if let Some(shared_to_me) = target.shared_to_me.as_mut() {
                shared_to_me.retain(|share| share.entity_uid != share_id);
            }

            // Remove the share from owner user's shared_to_others list
            if let Some(shared_to_others) = owner.shared_to_others.as_mut() {
                shared_to_others.retain(|share| share.entity_uid != share_id);
            }

            // Update the users in the database
            let target_updated = Database::update_user(&target);
            let owner_updated = Database::update_user(&owner);

            // Return success

            return if target_updated.is_ok() && owner_updated.is_ok() {
                Ok(())
            } else {
                Err("Error while updating user".to_string())
            };
        } else {
            // Return error if either user is not found
            Err("User not found".to_string())
        }
    }

    pub fn has_access_to_entity(user_id: &str, entity_id: &str) -> bool {
        // Retrieve the user from the database using the user_id
        if let Some(user) = Database::get_user_by_id(user_id) {
            // Check if the user's shared_to_me field is initialized
            if let Some(shared_to_me) = &user.shared_to_me {
                // Iterate over the shared_to_me list
                for share in shared_to_me {
                    // Check if the current share's entity_uid matches the provided entity_id
                    if share.entity_uid == entity_id {
                        // If a match is found, return true indicating the user has access
                        return true;
                    }
                }
            }
        }

        // If no match is found, or the user does not exist, return false
        false
    }
    pub fn get_user(username: &str) -> Option<User> {
        //info!("username to process: {}", username);

        if let Ok(database) = Self::get_all_users() {
            for user in database.users {
                if user.username == username {
                    return Some(user);
                }
            }
        }
        None
    }

    pub fn get_user_by_id(uid: &str) -> Option<User> {
        //info!("username to process: {}", uid);

        if let Ok(database) = Self::get_all_users() {
            for user in database.users {
                if user.uid == uid {
                    return Some(user);
                }
            }
        }
        None
    }

    pub fn add_user(new_user: User) -> std::io::Result<()> {
        let mut db_users = Self::get_all_users().unwrap();
        db_users.users.push(new_user.clone());

        fs::create_dir_all(Database::get_user_bucket(&new_user.uid)).unwrap();

        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(Self::get_users_db_path())
            .unwrap();

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &db_users).unwrap();
        writer.flush().unwrap();
        Ok(())
    }

    pub fn update_user(updated_user: &User) -> Result<(), ()> {
        let mut db_users = Self::get_all_users().unwrap();

        // Find the user and update their details
        if let Some(user) = db_users
            .users
            .iter_mut()
            .find(|u| u.uid == updated_user.uid)
        {
            *user = updated_user.clone();
        } else {
            // Return an error if user not found
            return Err(());
        }

        // Write the updated users list back to the database
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(Self::get_users_db_path())
            .unwrap();

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &db_users).unwrap();
        writer.flush().unwrap();

        Ok(())
    }

    pub fn get_public_key(username: &str) -> Option<PublicKeyMaterial> {
        if let Some(user) = Self::get_user(username) {
            Some(PublicKeyMaterial {
                public_key: user.public_key,
                owner_id: user.uid,
            })
        } else {
            None
        }
    }

    pub fn generate_jwt(user: &User) -> Result<String, Error> {
        let claims = JwtClaims {
            exp: get_current_timestamp() + 86400, // 24h lifetime
            iss: String::from("Cloud secured bucket"),
            sub: SubClaim {
                uid: user.uid.to_owned(),
                username: user.username.to_owned(),
            },
        };

        encode(
            &Header::new(Algorithm::HS512),
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
    }

    pub fn verify_token(token: &str) -> Result<JwtClaims, String> {
        match decode::<JwtClaims>(
            &token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::new(Algorithm::HS512),
        ) {
            Ok(decoded) => Ok(decoded.claims),
            Err(err) => Err(format!("Failed to decode JWT: {:?}", err)),
        }
    }

    pub fn change_password(user_2_update: User) -> std::io::Result<()> {
        let mut db_users = Self::get_all_users().unwrap();

        info!("size: {} {}", db_users.users.len(), user_2_update.uid);

        if let Some(index) = db_users
            .users
            .iter()
            .position(|user| user.uid == user_2_update.uid)
        {
            info!("Go");

            // update encrypted keys
            db_users.users[index].clear_salt = user_2_update.clear_salt;
            db_users.users[index].master_key = user_2_update.master_key;
            db_users.users[index].auth_key = user_2_update.auth_key;
            db_users.users[index].private_key = user_2_update.private_key;

            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(Self::get_users_db_path())
                .unwrap();

            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &db_users).unwrap();
            writer.flush().unwrap();

            Ok(())
        } else {
            info!("Unable to find");

            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "User not found",
            ))
        }
    }
}

/// JWT Structures
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtClaims {
    pub exp: u64,
    pub iss: String,
    #[serde(flatten)]
    pub sub: SubClaim,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct SubClaim {
    pub uid: String,
    pub username: String,
}

fn is_dir_empty(path: &str) -> std::io::Result<bool> {
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}
