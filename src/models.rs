use std::{
    collections::HashMap,
    fmt::format,
    fs::{self, File, OpenOptions},
    hash::Hash,
    io::{BufWriter, Write},
    path::Path,
};

use jsonwebtoken::{
    decode, encode, errors::Error, get_current_timestamp, Algorithm, DecodingKey, EncodingKey,
    Header, Validation,
};

use serde::{Deserialize, Serialize};

const SERVER_ROOT: &str = "vault";
const USERS_DB: &str = "users.json";
const METADATA: &str = "metadata.json";
const USERS_DIR: &str = "users";
// vault/users/USER_ID/metadata.json/
// vault/users/USER_ID/data/CIPHER_DIR

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    dirs: Vec<DirEntity>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DataStatus {
    // allow to know if the current processed data are encrypted or not
    Encrypted,
    Decrypted,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataAsset {
    // can contain encrypted/decrypted data
    pub asset: String,
    pub nonce: String,
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
    pub shared_to_others: Option<HashMap<String, String>>,
    pub shared_to_me: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DirEntity {
    // must be sent to the client while logged in
    pub path: String,
    pub name: DataAsset,
    pub key: DataAsset,
    pub files: Vec<FileEntity>,
    pub dirs: Option<Vec<DirEntity>>,
}

impl DirEntity {
    pub fn create(&self) -> bool {
        match fs::create_dir_all(&self.path) {
            Ok(_) => {
                // create metadata

                return true;
            }
            Err(e) => {
                eprintln!("Error while creating dir : {}", e);
                return false;
            }
        };
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileEntity {
    pub path: String,
    pub name: DataAsset,
    pub key: DataAsset,
    pub content: DataAsset,
}
impl FileEntity {
    pub fn create(&self) -> bool {
        let path = Path::new(&self.path);

        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Error while creating file : {}", e);
                return false;
            }
        };

        match file.write_all(self.content.asset.clone().as_bytes()) {
            Ok(_) => return true,
            Err(e) => {
                eprintln!("Error while filling content : {}", e);
                return false;
            }
        }
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

    pub fn get_user_metadata(uid: &str) -> String {
        format!("{}/{}/{}/{}", SERVER_ROOT, USERS_DIR, uid, METADATA)
    }

    fn get_user_bucket(uid: &str) -> String {
        format!("{}/{}/{}/bucket/", SERVER_ROOT, USERS_DIR, uid)
    }

    fn get_all_users() -> Result<Database, Box<dyn std::error::Error>> {
        Self::create_db_if_does_n_exist();
        let file_path = Database::get_users_db_path();
        let file_content = std::fs::read_to_string(&file_path)?;

        let database: Database = serde_json::from_str(&file_content)?;

        Ok(database)
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

    // use to update the user metadata while adding a new file
    /* fn add_to_dir_tree(uid: &str, file_entity: FileEntity) {
        // load content of the current metatadata for a "uid" user
        let metadata_path = Database::get_user_metadata(uid);
        let str_raw_metadata = std::fs::read_to_string(&metadata_path).unwrap();

        // Deserialize string to Metadata struct
        let mut metadata: Metadata =
            serde_json::from_str(&str_raw_metadata).expect("Unable to deserialize metadata");

        // Find the dir entity where add the file entity
        let mut current_dir = &mut metadata.dirs;
        for dir_name in file_entity.path.split('/') {
            // check if not empty
            if !dir_name.is_empty() {
                // if dir has been found
                if let Some(found_dir) = current_dir.iter_mut().find(|dir| {
                    String::from_utf8_lossy(dir.name.asset.unwrap().as_slice()).to_string()
                        == dir_name.to_string()
                }) {
                    current_dir = &mut found_dir.dirs.unwrap();
                } /*  else {
                        // check if needed
                      let new_dir = DirEntity {
                          path: format!("{}/{}", file_entity.path, dir_name),
                          name: DataAsset {
                              asset: Some(dir_name.into()),
                              nonce: None,
                              status: None,
                          },
                          key: DataAsset {
                              asset: None,
                              nonce: None,
                              status: None,
                          },
                          files: Vec::new(),
                          dirs: None,
                      };
                      current_dir.push(new_dir);
                      current_dir = &mut current_dir.last_mut().unwrap().dirs.unwrap();
                  } */
            }
        }

        // add the file in the the folder
        if let Some(last_dir) = current_dir.last_mut() {
            last_dir.files.push(file_entity);
        }

        // update the metadata
        let updated_metadata_content =
            serde_json::to_string(&metadata).expect("Unable to serialize metadata");

        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(metadata_path)
            .unwrap();

        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &updated_metadata_content).unwrap();
        writer.flush().unwrap();
    } */

    pub fn get_user(username: &str) -> Option<User> {
        if let Ok(database) = Self::get_all_users() {
            for user in database.users {
                if user.username == username {
                    return Some(user);
                }
            }
        }
        None
    }

    // use to get all files from a dir.
    //
    pub fn get_dir(path: DirEntity) {
        // get name from this path, then get the metadata from dir
        let server_root_path = Path::new(SERVER_ROOT);

        if !server_root_path.exists() {
            fs::create_dir_all(server_root_path).expect("Failed to create server root directory");
        }
    }

    pub fn add_user(new_user: User) -> std::io::Result<()> {
        let mut db_users = Self::get_all_users().unwrap();
        db_users.users.push(new_user);

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

    pub fn create_folder(dir: DirEntity, owner: User) -> std::io::Result<()> {
        // TODO check if dir

        let user_bucket = Self::get_user_bucket(&owner.uid);
        let folder_path = format!("{}/{}", user_bucket, dir.path);

        fs::create_dir_all(&folder_path).unwrap();

        Ok(())
    }

    pub fn create_file(file: FileEntity, owner: User) -> std::io::Result<()> {
        // TODO check if file

        let user_bucket = Self::get_user_bucket(&owner.uid);
        let file_path = format!("{}/{}", user_bucket, file.path);

        let mut sysfile = File::create(&file_path)?;
        sysfile.write_all(&file.content.asset.as_bytes().to_vec())?;

        Ok(())
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
