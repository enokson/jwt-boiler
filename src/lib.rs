#![forbid(unsafe_code)]

use digest::InvalidLength;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
pub use jwt::Error as JwtError;
pub use serde_json::{Value, to_value, from_value};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength(#[from] InvalidLength),
    #[error("signing error")]
    SignErr(#[from] JwtError),
}

fn hash_password(pass: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, pass));
    hex::encode(hasher.finalize().as_slice())
}

pub fn to_hash(pass: &str) -> String {
    let salt = uuid::Uuid::new_v4().to_string();
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, pass));
    format!("{}:{}", salt, hash_password(pass, &salt))
}

pub fn verify(pass: &str, safe_pass: &str) -> bool {
    let split: Vec<&str> = safe_pass.split(":").collect();
    let req_hash = hash_password(pass, split[0]);
    if req_hash == split[1] { true } else { false }
}

pub fn to_token(app_secret: &str, claims: BTreeMap<String, Value>) -> Result<String, Error> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(app_secret.as_bytes())?;
    let token = claims.sign_with_key(&key)?;
    Ok(token)
}

pub fn from_token(app_secret: &str, token: &str) -> Result<BTreeMap<String, Value>, Error> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(app_secret.as_bytes())?;
    let claims = token.verify_with_key(&key)?;
    Ok(claims)
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use serde_json::{from_value, to_value};
        
    #[test]
    fn hash_test() {
        let pass = "foo";
        let hash = to_hash(pass);
        assert!(verify(pass, &hash));
        assert!(!verify("bar", &hash));
    }

    #[test]
    fn sign_test() {
        let app_secret = "my-secret";
        let user_id = 1;
        let jwt = to_token(app_secret, [
            ("id".into(), to_value(user_id).unwrap())
        ].into()).unwrap();
        let mut claims = from_token(app_secret, &jwt).unwrap();
        assert_eq!(1, from_value::<i32>(claims.remove("id").unwrap()).unwrap());

    }

}
