pub mod models;

extern crate rocket;

use models::{Database, DirEntity, FileEntity, User};
use rocket::http::Status;
use rocket::response::status;
use rocket::*;
use uuid::Uuid;
// TODO !!!!! REMOVE ERROR FROM PAYLOAD RESPONSE
/// Authentication status: None
#[get("/get_salt/<username>")]
pub fn get_salt(username: &str) -> status::Custom<String> {
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
#[get("/get_sign_up", data = "<new_user>")]
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
                Ok(jwt) => return status::Custom(Status::Ok, jwt),
                Err(_) => return generic_error,
            };
        }
        Err(_) => return generic_error,
    }
}

#[post("/file/create?<token>", data = "<file_as_str>")]
pub fn post_file(token: &str, file_as_str: &str) -> status::Custom<String> {
    let generic_error = status::Custom(
        Status::BadRequest,
        "You are not authorized to perform this action".to_string(),
    );
    let success = status::Custom(Status::Ok, "File successfully created".to_string());

    match Database::verify_token(token) {
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
                return success;
            } else {
                return generic_error;
            }
        }
        Err(_) => return generic_error,
    }
}

#[post("/dir/create?<token>", data = "<dir_as_str>")]
pub fn post_dir(token: &str, dir_as_str: &str) -> status::Custom<String> {
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

#[post("/auth/change_password?<token>", data = "<user>")]
pub fn post_change_password(token: &str, user: &str) {}

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
