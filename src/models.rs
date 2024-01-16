use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
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
    pub shared_to_others: Option<HashMap<String, String>>, // uid
    pub shared_to_me: Option<HashMap<String, String>>,
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

        println!("{}", path_2_create.clone());

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
                    eprintln!("Error while creating dir : {}", e);
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

    pub fn get_user(username: &str) -> Option<User> {
        info!("username to process: {}", username);

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
        info!("username to process: {}", uid);

        if let Ok(database) = Self::get_all_users() {
            for user in database.users {
                if user.uid == uid {
                    return Some(user);
                }
            }
        }
        None
    }

    // use to get all files from a dir.
    //
    pub fn get_dir(path: FsEntity) {
        // get name from this path, then get the metadata from dir
        let server_root_path = Path::new(SERVER_ROOT);

        if !server_root_path.exists() {
            fs::create_dir_all(server_root_path).expect("Failed to create server root directory");
        }
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

    pub fn create_folder(dir: FsEntity, owner: User) -> std::io::Result<()> {
        // TODO check if dir

        let user_bucket = Self::get_user_bucket(&owner.uid);
        let folder_path = format!("{}/{}", user_bucket, dir.path);

        fs::create_dir_all(&folder_path).unwrap();

        Ok(())
    }

    /*     pub fn create_file(file: FileEntity, owner: User) -> std::io::Result<()> {
        // TODO check if file

        let user_bucket = Self::get_user_bucket(&owner.uid);
        let file_path = format!("{}/{}", user_bucket, file.path);

        let mut sysfile = File::create(&file_path)?;
        sysfile.write_all(&file.content.asset.unwrap().as_bytes().to_vec())?;

        Ok(())
    } */

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

        if let Some(index) = db_users
            .users
            .iter()
            .position(|user| user.uid == user_2_update.uid)
        {
            // update encrypted keys
            db_users.users[index].clear_salt = user_2_update.clear_salt;
            db_users.users[index].auth_key = user_2_update.auth_key;
            db_users.users[index].master_key = user_2_update.master_key;
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
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "User not found",
            ))
        }
    }
}

/// JWT Structures
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub exp: u64,
    pub iss: String,
    #[serde(flatten)]
    pub sub: SubClaim,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct SubClaim {
    pub uid: String,
    pub username: String,
}

fn is_dir_empty(path: &str) -> std::io::Result<bool> {
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}
