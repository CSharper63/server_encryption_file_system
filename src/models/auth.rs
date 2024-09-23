use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

use super::user::User;

// !! THIS MUST BE SET IN ENV VARIABLE AND NOT PUSHED IN PROD ENV LIKE THIS
const JWT_SECRET_KEY: &str = "this_is_my_secret_symm_key";

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

impl JwtClaims {
    pub fn generate_jwt(user: &User) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = JwtClaims {
            exp: get_current_timestamp() + 86400, // 24h lifetime
            iss: String::from("Cloud secured bucket"),
            sub: SubClaim {
                uid: user.uid.to_owned(),
                username: user.username.to_owned(),
            },
        };

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET_KEY.as_ref()), // !! POC only, must be stored in HSM
        )
    }

    pub fn verify_token(token: &str) -> Result<JwtClaims, String> {
        let Ok(decoded) = decode::<JwtClaims>(
            &token,
            &DecodingKey::from_secret(JWT_SECRET_KEY.as_ref()),
            &Validation::new(Algorithm::HS256),
        ) else {
            return Err("Failed to decode JWT".into());
        };

        Ok(decoded.claims)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyMaterial {
    pub public_key: String,
    pub owner_id: String,
}

impl PublicKeyMaterial {
    pub fn new(public_key: String, owner_id: String) -> Self {
        PublicKeyMaterial {
            public_key,
            owner_id,
        }
    }
}
