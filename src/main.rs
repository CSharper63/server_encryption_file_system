pub mod models;

extern crate rocket;

use std::io::Write;

use log::private::{debug, info};
use models::{Database, FsEntity, RootTree, User};
use rocket::http::Status;
use rocket::response::status;
use rocket::*;
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

    info!(
        "Username: {}\nAuth key: {}",
        username.clone(),
        auth_key.clone()
    );

    let db_user = match Database::get_user(username.as_str()) {
        Some(user) => user,
        None => return generic_error,
    };

    // must check the auth key
    // must be encoded in base58
    if auth_key == db_user.auth_key {
        std::io::stdout().flush().unwrap();

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
                    info!("this the nonce {}", user.clone().master_key.nonce.unwrap());

                    return status::Custom(Status::Ok, serde_json::to_string(&user).unwrap());
                }
                None => return generic_error,
            };
        }
        Err(_) => return unauthorized_access,
    }
}

/// Authentication status: None
#[get("/get_sign_up", format = "json", data = "<new_user>")]
pub fn get_sign_up(new_user: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to sign up".to_string());

    println!("fetched user: {}", new_user);

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
    info!("before sanitize: {}", new_user.username);

    new_user.username = remove_whitespace(new_user.username.to_lowercase().as_str());

    info!("after sanitize: {}", new_user.username);

    new_user.uid = Uuid::new_v4().to_string(); // set new PK for DB

    // verify that the user does not already exist
    match Database::get_user(&new_user.username) {
        Some(_) => return generic_error,
        None => {}
    }

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
#[post("/file/create/<auth_token>", data = "<file_as_str>")]
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
                return generic_error;
            }
        }
        Err(_) => return generic_error,
    }
}

//todo  get_my_tree?auth_token=

// todo file/get?token={}?path={}

// todo /auth/get_public_key?username={}?auth_token={}

// todo /share/username={}?auth_token={}?path={}?shared_key={}

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

/* #[get("/dir/get/<token>", data = "<dir_path>")]
pub fn get_dir(token: &str, dir_path: &str) -> status::Custom<DirEntity> {
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );
    match Database::verify_token(token) {
        Ok(jwt) => {
            let user_id = jwt.sub.uid;

            let dir = Database::get_dir(path);

            return generic_error;
        }
        Err(_) => return generic_error,
    }
} */

// TODO add get_public_key by username

#[post("/auth/change_password?<token>", data = "<user>")]
pub fn post_change_password(token: &str, user: &str) -> status::Custom<String> {
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );

    let success = status::Custom(Status::Ok, "Password updated successfully".to_string());

    match Database::verify_token(token) {
        Ok(verified_token) => {
            // convert body to struct
            let user_2_update: User = match serde_json::from_str(user) {
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

            if user_2_update.uid == verified_token.sub.uid {
                match Database::change_password(user_2_update) {
                    Ok(_) => {
                        return success;
                    }
                    Err(_) => {
                        return generic_error;
                    }
                };
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

fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[launch]
fn rocket() -> Rocket<Build> {
    build().mount(
        "/",
        routes![
            get_salt,
            get_user,
            get_sign_in,
            get_sign_up,
            post_dir,
            post_file,
            post_change_password,
            get_my_tree,
            post_tree,
            get_children
        ],
    )
}
