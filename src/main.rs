use api::*;
use rocket::shield::{Hsts, Shield};
use rocket::*;
use rocket_dyn_templates::Template;
//use views::*;

pub mod api;
pub mod models;
//pub mod views;

extern crate rocket;

#[launch]
fn rocket() -> Rocket<Build> {
    let max_age_two_years = rocket::time::Duration::new(63072000, 0);

    rocket::build()
        .attach(Template::fairing())
        .attach(Shield::default().enable(Hsts::Enable(max_age_two_years))) // HSTS force HTTPS
        .mount(
            "/",
            routes![
                // api
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
                get_shared_children,
                get_shared_entity,
                get_file_content,
                // view
                //view_home
            ],
        )
}
