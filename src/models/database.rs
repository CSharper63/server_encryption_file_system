use rocket::log::private::info;
use std::{
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::{auth::PublicKeyMaterial, data_asset::Sharing, fs_entity::FsEntity, user::User};

const SERVER_ROOT: &str = "vault";
const USERS_DB: &str = "users.json";
const USERS_DIR: &str = "users";

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

    pub fn get_user_bucket(uid: &str) -> String {
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

    pub fn add_to_dir_tree(
        owner_id: &str,
        element: &FsEntity,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut root = Database::get_root_tree(owner_id)?;

        if let Some(elements) = &mut root.elements {
            elements.push(element.clone());
        }

        let root_str = serde_json::to_string(&root).unwrap();
        fs::write(
            Database::get_user_metadata_path(owner_id),
            root_str.as_bytes(),
        )
        .expect("Failed to update user root metadata");
        return Ok(String::from("Element successfully added to tree"));
    }

    pub fn get_elem_from_tree(
        owner_id: &str,
        element_id: &str,
    ) -> Result<FsEntity, Box<dyn std::error::Error>> {
        let root = Database::get_root_tree(owner_id)?;
        for e in root.elements.unwrap().iter() {
            if e.uid == element_id {
                return Ok(e.clone());
            }
        }

        return Err("Cannot get the element".into());
    }

    pub fn get_children(
        owner_id: &str,
        parent_id: &str,
    ) -> Result<Vec<FsEntity>, Box<dyn std::error::Error>> {
        let root = Database::get_root_tree(owner_id)?;
        let mut all_children: Vec<FsEntity> = Vec::default();

        for e in root.elements.unwrap().iter() {
            if e.parent_id == parent_id {
                info!("We found something intersting");
                all_children.push(e.clone());
            }
        }

        return Ok(all_children);
    }

    pub fn get_entity(
        owner_id: &str,
        entity_id: &str,
    ) -> Result<FsEntity, Box<dyn std::error::Error>> {
        let root = Database::get_root_tree(owner_id)?;

        for e in root.elements.unwrap().iter() {
            if e.uid == entity_id {
                info!("We found something intersting");
                return Ok(e.clone());
            }
        }

        return Err("Cannot get the entity".into());
    }
    pub fn get_entity_path(
        owner_id: &str,
        entity_id: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let root = Database::get_root_tree(owner_id)?;

        for e in root.elements.unwrap().iter() {
            if e.clone().uid == entity_id {
                info!("We found something intersting");

                let path = if e.path.is_empty() {
                    format!(
                        "{}/{}{}",
                        Database::get_user_bucket(owner_id),
                        e.path,
                        e.name.asset.clone().unwrap()
                    )
                } else {
                    format!(
                        "{}/{}/{}",
                        Database::get_user_bucket(owner_id),
                        e.path,
                        e.name.asset.clone().unwrap()
                    )
                };

                return Ok(path);
            }
        }
        return Err("Cannot find entity path".into());
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

    pub fn init_root_tree(uid: &str) -> Result<(), Box<dyn std::error::Error>> {
        // by default three is no content in the root dir
        let root_tree = RootTree {
            elements: Some(Vec::default()),
        };

        let root_str = serde_json::to_string(&root_tree)?;

        // write metadata to User space
        fs::write(Database::get_user_metadata_path(uid), root_str.as_bytes())
            .expect("Failed to create user root metadata");

        Ok(())
    }

    pub fn get_root_tree(uid: &str) -> Result<RootTree, Box<dyn std::error::Error>> {
        let file_content = std::fs::read_to_string(&Database::get_user_metadata_path(uid)).unwrap();

        let Ok(tree) = serde_json::from_str(&file_content) else {
            return Err("Cannot get the root tree".into());
        };

        Ok(tree)
    }
    pub fn share(shares: &Sharing) -> Result<(), Box<dyn std::error::Error>> {
        let (Ok(mut target_user), Ok(mut owner_user)) = (
            Database::get_user_by_id(&shares.user_id),
            Database::get_user_by_id(&shares.owner_id),
        ) else {
            return Err("Cannot get user".into());
        };

        // Initialize vectors if they are None
        target_user.shared_to_me.get_or_insert_with(Vec::new);
        owner_user.shared_to_others.get_or_insert_with(Vec::new);

        let (Some(target_shared_to_me), Some(owner_shared_to_others)) = (
            target_user.shared_to_me.as_mut(),
            owner_user.shared_to_others.as_mut(),
        ) else {
            return Err("Cannot get sharing list for users".into());
        };

        // Check and add share to target user if not exists
        if !target_shared_to_me
            .iter()
            .any(|existing_share| existing_share.entity_uid == shares.entity_uid)
        {
            target_shared_to_me.push(shares.clone());
            Database::update_user(&target_user)?;
        }

        // Check and add share to owner user if not exists
        if !owner_shared_to_others
            .iter()
            .any(|existing_share| existing_share.entity_uid == shares.entity_uid)
        {
            owner_shared_to_others.push(shares.clone());
            Database::update_user(&owner_user)?;
        }

        Ok(())
    }

    pub fn revoke_share(
        share_id: &str,
        user_id: &str,
        owner_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (Ok(mut target_user), Ok(mut owner_user)) = (
            Database::get_user_by_id(user_id),
            Database::get_user_by_id(owner_id),
        ) else {
            return Err("Cannot get user".into());
        };
        // Check if both users are found
        // Remove the share from target user's shared_to_me list
        if let Some(shared_to_me) = target_user.shared_to_me.as_mut() {
            shared_to_me.retain(|share| share.entity_uid != share_id);
        }

        // Remove the share from owner user's shared_to_others list
        if let Some(shared_to_others) = owner_user.shared_to_others.as_mut() {
            shared_to_others.retain(|share| share.entity_uid != share_id);
        }

        // Update the users in the database
        let target_updated = Database::update_user(&target_user);
        let owner_updated = Database::update_user(&owner_user);

        return if target_updated.is_ok() && owner_updated.is_ok() {
            Ok(())
        } else {
            Err("Error while updating user".into())
        };
    }

    pub fn has_access_to_entity(
        user_id: &str,
        entity_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let user = Database::get_user_by_id(user_id)?;

        let Some(shared_to_me) = &user.shared_to_me else {
            return Ok(false);
        };

        let Some(_) = shared_to_me.iter().find(|s| s.entity_uid == entity_id) else {
            return Ok(false);
        };

        Ok(true)
    }

    pub fn get_user(username: &str) -> Result<User, Box<dyn std::error::Error>> {
        let Ok(db) = Self::get_all_users() else {
            return Err("Database unreachable".into());
        };

        let Some(user) = db.users.iter().find(|u| u.username == username) else {
            return Err("User not found".into());
        };
        Ok(user.clone())
    }

    pub fn get_user_by_id(uid: &str) -> Result<User, Box<dyn std::error::Error>> {
        let Ok(db) = Self::get_all_users() else {
            return Err("Database unreachable".into());
        };

        let Some(user) = db.users.iter().find(|u| u.uid == uid) else {
            return Err("User not found".into());
        };

        Ok(user.clone())
    }

    pub fn add_user(new_user: &User) -> Result<(), Box<dyn std::error::Error>> {
        info!("inserted hmac {}", new_user.auth_key);
        let mut db_users = Self::get_all_users()?;
        db_users.users.push(new_user.clone());

        fs::create_dir_all(Database::get_user_bucket(&new_user.uid))?;

        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(Self::get_users_db_path())
            .unwrap();

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &db_users)?;
        writer.flush().unwrap();
        Ok(())
    }

    pub fn update_user(updated_user: &User) -> Result<(), Box<dyn std::error::Error>> {
        let mut db_users = Self::get_all_users()?;

        let Some(user) = db_users
            .users
            .iter_mut()
            .find(|u| u.uid == updated_user.uid)
        else {
            return Err("Cannot update user".into());
        };

        *user = updated_user.clone();

        // Write the updated users list back to the database
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(Self::get_users_db_path())
            .unwrap();

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &db_users)?;
        writer.flush()?;

        Ok(())
    }

    pub fn get_public_key(username: &str) -> Result<PublicKeyMaterial, Box<dyn std::error::Error>> {
        let Ok(user) = Self::get_user(username) else {
            return Err("No public key found".into());
        };

        let pk = PublicKeyMaterial::new(user.public_key, user.uid);
        Ok(pk)
    }

    pub fn change_password(user_2_update: User) -> Result<(), Box<dyn std::error::Error>> {
        let mut db_users = Self::get_all_users()?;

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
                .open(Self::get_users_db_path())?;

            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &db_users)?;
            writer.flush()?;

            Ok(())
        } else {
            info!("Unable to find");

            Err("User not found".into())
        }
    }
}
