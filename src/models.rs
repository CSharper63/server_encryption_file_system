use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{
    decode, encode, errors::Error, get_current_timestamp, Algorithm, DecodingKey, EncodingKey,
    Header, Validation,
};
use rocket::{
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest, Request},
    FromForm,
};

use serde::{Deserialize, Serialize};

const SERVER_ROOT: &str = "vault";
const USERS_DB: &str = "users.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedAsset {
    pub asset: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub uid: String,
    pub username: String,
    pub clear_salt: String,
    pub encrypted_master_key: EncryptedAsset,
    pub auth_key: String,
    pub public_key: String,
    pub encrypted_private_key: EncryptedAsset,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DirEntity {
    // must be sent to the client while logged in
    pub path: String,
    pub encrypted_name: EncryptedAsset,
    pub encrypted_key: EncryptedAsset,
    pub files: Vec<FileEntity>,
    pub dirs: Vec<DirEntity>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileEntity {
    pub path: String,
    pub encrypted_name: EncryptedAsset,
    pub encrypted_key: EncryptedAsset,
    pub encrypted_content: EncryptedAsset,
}

impl FileEntity {
    pub fn decode_b64(str: &str) -> Vec<u8> {
        general_purpose::STANDARD.decode(str).unwrap()
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

    fn get_user_bucket(uid: &str) -> String {
        format!("{}/buckets/{}", SERVER_ROOT, uid)
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
        sysfile.write_all(&FileEntity::decode_b64(&file.encrypted_content.asset))?;

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
}

/// JWT Structures
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    exp: u64,
    iss: String,
    #[serde(flatten)]
    sub: SubClaim,
}

#[derive(Serialize, Debug, Deserialize)]
struct SubClaim {
    uid: String,
    username: String,
}
