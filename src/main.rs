pub mod models;

extern crate rocket;

use std::time::Duration;

use blake2::Digest;

use jsonwebtoken::Header;
use log::private::info;
use models::{Database, FsEntity, PublicKeyMaterial, RootTree, Sharing, User};
use rocket::config::{CipherSuite, TlsConfig};
use rocket::data::ByteUnit;
use rocket::fairing::Fairing;
use rocket::response::status;
use rocket::shield::{Hsts, Shield};
use rocket::*;
use rocket::{data::Limits, http::Status};
use uuid::Uuid;

// TODO !!!!! REMOVE ERROR FROM PAYLOAD RESPONSE
/// Authentication status: None
#[get("/auth/get_salt?<username>")]
pub fn get_salt(username: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to get salt".to_string());
    let username = remove_whitespace(username.to_lowercase().as_str());

    match Database::get_user(username.as_str()) {
        Some(user) => return status::Custom(Status::Ok, user.clear_salt),
        None => return generic_error,
    };
}

/// Authentication status: None
#[get("/get_sign_in?<username>&<auth_key>")]
pub fn get_sign_in(username: &str, auth_key: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to sign in".to_string());

    // sanitize input
    let username = remove_whitespace(&username.to_lowercase());
    let auth_key = auth_key.trim();

    // hash the client auth key to check if the same as the stored server one.

    let mut hasher = blake2::Blake2s256::new();
    let decoded_auth_key = bs58::decode(auth_key).into_vec().unwrap();
    hasher.update(decoded_auth_key);
    // hash digest into bs58 str
    let client_auth_key = bs58::encode(hasher.finalize()).into_string();

    let db_user = match Database::get_user(username.as_str()) {
        Some(user) => user,
        None => return generic_error,
    };

    // must check the auth key
    // must be encoded in base58
    if client_auth_key == db_user.auth_key {
        // must create a JWT
        match Database::generate_jwt(&db_user) {
            Ok(jwt) => return status::Custom(Status::Ok, jwt),
            Err(e) => {
                return status::Custom(
                    Status::BadRequest,
                    format!("{} , {}", e.to_string(), "Unable to sign in".to_string()),
                )
            }
        };
    } else {
        return status::Custom(
            Status::BadRequest,
            format!("{}", "Does not match".to_string()),
        );
    }
}

/// Authentication status: None
#[get("/get_user?<auth_token>")]
pub fn get_user(auth_token: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to fetch the user".to_string());
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    // must check the auth key
    // must be encoded in base58
    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            // convert body to struct
            match Database::get_user_by_id(&jwt.sub.uid) {
                Some(user) => {
                    return status::Custom(Status::Ok, serde_json::to_string(&user).unwrap());
                }
                None => return generic_error,
            };
        }
        Err(_) => return unauthorized_access,
    }
}

#[post(
    "/auth/update_password?<auth_token>",
    format = "json",
    data = "<updated_user>"
)]
pub fn post_update_password(auth_token: &str, updated_user: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to sign up".to_string());

    // convert body to struct
    let mut updated_user: User = match serde_json::from_str(updated_user) {
        Ok(c) => c,
        Err(e) => {
            return status::Custom(
                Status::BadRequest,
                format!(
                    "error: {}. {}",
                    e.to_string(),
                    "Please provide me a json".to_string()
                ),
            )
        }
    };

    match Database::verify_token(auth_token) {
        Ok(_) => {
            // convert body to struct
            // verify that the user does not already exist
            match Database::get_user(&updated_user.username) {
                Some(_) => {
                    // hash the auth key -> case of data leak, as auth key must be sent to server and then hashed.
                    // The attacker is unable to rollback the auth_key
                    let mut hasher = blake2::Blake2s256::new();
                    let decoded_auth_key = bs58::decode(updated_user.clone().auth_key)
                        .into_vec()
                        .unwrap();
                    hasher.update(decoded_auth_key);

                    // hash digest into bs58 str
                    updated_user.auth_key = bs58::encode(hasher.finalize()).into_string();

                    println!("UID: {}", updated_user.uid);

                    // add user in db
                    match Database::change_password(updated_user.clone()) {
                        Ok(_) => {
                            // after successfully add user, sent the JWT to access to the service
                            match Database::generate_jwt(&updated_user) {
                                Ok(jwt) => return status::Custom(Status::Ok, jwt),
                                Err(_) => {
                                    info!("Cannot generate jwt");
                                    return generic_error;
                                }
                            };
                        }
                        Err(_) => {
                            info!("Cannot change the password");
                            return generic_error;
                        }
                    }
                }
                None => {
                    info!("Invalid authentification token");
                    return generic_error;
                }
            }
        }
        Err(_) => {
            info!("User invalid token");
            return generic_error;
        }
    }
}

/// Authentication status: None
#[get("/get_sign_up", format = "json", data = "<new_user>")]
pub fn get_sign_up(new_user: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to sign up".to_string());

    // convert body to struct
    let mut new_user: User = match serde_json::from_str(new_user) {
        Ok(c) => c,
        Err(e) => {
            return status::Custom(
                Status::BadRequest,
                format!(
                    "error: {}. {}",
                    e.to_string(),
                    "Please provide me a json".to_string()
                ),
            )
        }
    };

    // sanitize username
    new_user.username = remove_whitespace(new_user.username.to_lowercase().as_str());

    new_user.uid = Uuid::new_v4().to_string(); // set new PK for DB

    // verify that the user does not already exist
    match Database::get_user(&new_user.username) {
        Some(_) => return generic_error,
        None => {}
    }

    // hash the auth key -> case of data leak, as auth key must be sent to server and then hashed.
    // The attacker is unable to rollback the auth_key
    let mut hasher = blake2::Blake2s256::new();
    let decoded_auth_key = bs58::decode(new_user.clone().auth_key).into_vec().unwrap();
    hasher.update(decoded_auth_key);

    // hash digest into bs58 str
    new_user.auth_key = bs58::encode(hasher.finalize()).into_string();

    // add user in db
    match Database::add_user(new_user.clone()) {
        Ok(_) => {
            // init root tree
            Database::init_root_tree(&new_user.uid);

            // after successfully add user, sent the JWT to access to the service
            match Database::generate_jwt(&new_user) {
                Ok(jwt) => return status::Custom(Status::Created, jwt),
                Err(_) => return generic_error,
            };
        }
        Err(_) => return generic_error,
    }
}

// when creating a file, the content won't be added in the metadata tree, the content will be directly stored in the file itself
// so when the user log in his session, it fetch is whole tree which contains only the tree with each encrypted key. If the user the
#[post("/file/create?<auth_token>", data = "<file_as_str>")]
pub fn post_file(auth_token: &str, file_as_str: &str) -> status::Custom<String> {
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );
    let success = status::Custom(Status::Ok, "File successfully created".to_string());

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            // convert body to struct
            let mut file: FsEntity = match serde_json::from_str(file_as_str) {
                Ok(c) => c,
                Err(e) => {
                    return status::Custom(
                        Status::BadRequest,
                        format!(
                            "error: {}. {}",
                            e.to_string(),
                            "Please provide me a json".to_string()
                        ),
                    )
                }
            };

            if file.create(&jwt.sub.uid.clone()) {
                // update the tree
                // get the parent dir and add it into

                return success;
            } else {
                info!("Problem during file creation");
                return generic_error;
            }
        }
        Err(_) => {
            info!("User invalid token");
            return generic_error;
        }
    }
}

//todo  get_my_tree?auth_token=

// todo file/get?token={}?path={}

// todo /auth/get_public_key?username={}?auth_token={}

// todo /share/username={}?auth_token={}?path={}?shared_key={}

#[post("/share?<auth_token>", format = "json", data = "<sharing>")]
pub fn post_share(auth_token: &str, sharing: &str) -> status::Custom<String> {
    let share: Sharing = serde_json::from_str(sharing).unwrap();
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );

    // must check that the owner_id is the same as the jwt
    // must check that the entity exist in the owner id bucket
    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            // convert body to struct
            if share.owner_id == jwt.sub.uid {
                // add this sharing to the right user name

                let shares = Database::get_elem_from_tree(&jwt.sub.uid, &share.entity_uid);

                if shares.is_none() {
                    println!("Nothing to share");
                    return generic_error;
                } else {
                    let success = status::Custom(
                        Status::Ok,
                        format!("{} shared successfully", shares.unwrap().entity_type),
                    );

                    // thing that I share, user I share with
                    match Database::share(&share) {
                        Some(_) => return success,
                        None => return generic_error,
                    };
                }
            } else {
                return generic_error;
            }
        }
        Err(_) => return generic_error,
    }
}

#[post("/revoke_share?<auth_token>", format = "json", data = "<sharing>")]
pub fn revoke_access(auth_token: &str, sharing: &str) -> status::Custom<String> {
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );
    let shares: Sharing = serde_json::from_str(sharing).unwrap();

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            if jwt.sub.uid == shares.owner_id {
                match Database::revoke_share(&shares.entity_uid, &shares.user_id, &shares.owner_id)
                {
                    Ok(_) => {
                        let success = status::Custom(Status::Ok, format!("Revoked successfully"));
                        return success;
                    }
                    Err(_) => return generic_error,
                }
            } else {
                return generic_error;
            }
        }
        Err(_) => return generic_error,
    }
}

#[post("/dir/create?<auth_token>", format = "json", data = "<dir_as_str>")]
pub fn post_dir(auth_token: &str, dir_as_str: &str) -> status::Custom<String> {
    let mut new_dir: FsEntity = serde_json::from_str(dir_as_str).unwrap();
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );

    let success = status::Custom(Status::Ok, "Directory successfully created".to_string());

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            // convert body to struct

            if new_dir.create(&jwt.sub.uid) {
                return success;
            } else {
                return generic_error;
            }
        }
        Err(_) => return generic_error,
    }
}

#[get("/get_my_tree?<auth_token>")]
pub async fn get_my_tree(auth_token: &str) -> status::Custom<String> {
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    let something_went_wrong =
        status::Custom(Status::BadRequest, "Something went wrong".to_string());

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            match Database::get_root_tree(&jwt.sub.uid) {
                Some(tree) => {
                    let tree_str = serde_json::to_string(&tree).unwrap();
                    return status::Custom(Status::Ok, tree_str);
                }
                None => return something_went_wrong,
            };
        }
        Err(_) => return unauthorized_access,
    }
}

#[get("/dirs/get_children?<auth_token>&<parent_id>")]
pub async fn get_children(auth_token: &str, parent_id: &str) -> status::Custom<String> {
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    let something_went_wrong =
        status::Custom(Status::BadRequest, "Something went wrong".to_string());

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            match Database::get_children(&jwt.sub.uid, parent_id) {
                Some(list_children) => {
                    let tree_str = serde_json::to_string(&list_children).unwrap();
                    return status::Custom(Status::Ok, tree_str);
                }
                None => return something_went_wrong,
            };
        }
        Err(_) => return unauthorized_access,
    }
}

#[get(
    "/dirs/get_shared_children?<auth_token>",
    format = "json",
    data = "<shares>"
)]
pub fn get_shared_children(auth_token: &str, shares: &str) -> status::Custom<String> {
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    let shares: Sharing = serde_json::from_str(shares).unwrap();

    let something_went_wrong =
        status::Custom(Status::BadRequest, "Something went wrong".to_string());

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            let has_access =
                Database::has_access_to_entity(&jwt.clone().sub.uid, &shares.entity_uid);

            if !has_access {
                return unauthorized_access;
            }

            info!("UID: {}", shares.clone().entity_uid);

            match Database::get_children(&shares.owner_id, &shares.entity_uid) {
                Some(list_children) => {
                    info!("Taille de la liste: {}", list_children.len());
                    let tree_str = serde_json::to_string(&list_children).unwrap();

                    return status::Custom(Status::Ok, tree_str);
                }
                None => return something_went_wrong,
            };
        }
        Err(_) => return unauthorized_access,
    }
}

#[post("/tree/update?<auth_token>", format = "json", data = "<updated_tree>")]
pub async fn post_tree(auth_token: &str, updated_tree: &str) -> status::Custom<String> {
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    let something_went_wrong =
        status::Custom(Status::BadRequest, "Something went wrong".to_string());

    let root_tree: RootTree = serde_json::from_str(updated_tree).unwrap();

    match Database::verify_token(auth_token) {
        Ok(jwt) => {
            Database::update_tree(&jwt.sub.uid, &root_tree);
            return status::Custom(Status::Ok, "Tree updated successfully".to_string());
        }
        Err(_) => return unauthorized_access,
    }
}

#[get("/auth/get_public_key?<auth_token>&<username>")]
pub fn get_public_key(auth_token: &str, username: &str) -> status::Custom<String> {
    let unauthorized_access = status::Custom(
        Status::Unauthorized,
        "You are not authorized to perform this action".to_string(),
    );

    match Database::verify_token(auth_token) {
        Ok(jwt) => match Database::get_public_key(username) {
            Some(public_key_material) => {
                return status::Custom(
                    Status::Ok,
                    serde_json::to_string(&public_key_material).unwrap(),
                );
            }
            None => status::Custom(
                Status::NotFound,
                "User not found or public key unavailable".to_string(),
            ),
        },
        Err(_) => return unauthorized_access,
    }
}

fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[launch]
fn rocket() -> Rocket<Build> {
    let max_age_two_years = rocket::time::Duration::new(63072000, 0);

    rocket::build()
        .attach(Shield::default().enable(Hsts::Enable(max_age_two_years))) // HSTS force HTTPS
        .mount(
            "/",
            routes![
                get_salt,
                get_user,
                get_sign_in,
                get_sign_up,
                post_dir,
                post_file,
                post_update_password,
                get_my_tree,
                post_tree,
                get_children,
                revoke_access,
                post_share,
                get_public_key,
                get_shared_children
            ],
        )
        .manage(Limits::new())
}
