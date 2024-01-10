pub mod models;

extern crate rocket;

use models::{Database, DirEntity, FileEntity, User};
use rocket::http::Status;
use rocket::response::status;
use rocket::*;
use uuid::Uuid;
// TODO !!!!! REMOVE ERROR FROM PAYLOAD RESPONSE
/// Authentication status: None
#[get("/auth/get_salt/<username>?<auth_key>")]
pub fn get_salt(username: &str, auth_key: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to get salt".to_string());

    match Database::get_user(username) {
        Some(user) => return status::Custom(Status::Ok, user.clear_salt),
        None => return generic_error,
    };
}

/// Authentication status: None
#[get("/get_sign_in/<username>?<auth_key>")]
pub fn get_sign_in(username: &str, auth_key: &str) -> status::Custom<String> {
    let generic_error = status::Custom(Status::BadRequest, "Unable to sign in".to_string());
    let db_user = match Database::get_user(username) {
        Some(user) => user,
        None => return generic_error,
    };

    // must check the auth key
    if auth_key == db_user.auth_key {
        // must create a JWT
        match Database::generate_jwt(&db_user) {
            Ok(jwt) => return status::Custom(Status::Ok, jwt),
            Err(_) => return generic_error,
        };
    } else {
        return generic_error;
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

    new_user.uid = Uuid::new_v4().to_string(); // set new PK for DB

    // verify that the user does not already exist
    match Database::get_user(&new_user.username) {
        Some(_) => return generic_error,
        None => {}
    }

    // add user in db
    match Database::add_user(new_user.clone()) {
        Ok(_) => {
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
        Ok(_) => {
            // convert body to struct
            let file: FileEntity = match serde_json::from_str(file_as_str) {
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

            if file.create() {
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

#[post("/dir/create?<token>", data = "<dir_as_str>")]
pub fn post_dir(token: &str, dir_as_str: &str) -> status::Custom<String> {
    let mut new_dir: DirEntity = serde_json::from_str(dir_as_str).unwrap();
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );

    let success = status::Custom(Status::Ok, "Directory successfully created".to_string());

    match Database::verify_token(token) {
        Ok(_) => {
            // convert body to struct
            let dir: DirEntity = match serde_json::from_str(dir_as_str) {
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

            if dir.create() {
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

#[launch]
fn rocket() -> Rocket<Build> {
    build().mount(
        "/",
        routes![
            get_salt,
            get_sign_in,
            get_sign_up,
            post_dir,
            post_file,
            post_change_password
        ],
    )
}
