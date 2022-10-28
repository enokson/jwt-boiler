
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey, Error as JwtError};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum Error {
    Hmac,
    Jwt(JwtError)
}

pub fn hash_password(pass: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, pass));
    hex::encode(hasher.finalize().as_slice())
}

pub fn create_safe_pass(pass: &str) -> String {
    let salt = uuid::Uuid::new_v4().to_string();
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, pass));
    format!("{}:{}", salt, hash_password(pass, &salt))
}

pub fn verify_pass(pass: &str, safe_pass: &str) -> bool {
    let split: Vec<&str> = safe_pass.split(":").collect();
    let req_hash = hash_password(pass, split[0]);
    if req_hash == split[1] { true } else { false }
}

pub fn sign<T: Into<String>>(app_secret: &str, user_id: T) -> Result<String, Error> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(app_secret.as_bytes()).unwrap();
    let claims: BTreeMap<&str, String> = [ ("id", user_id.into()) ].into();
    let token = claims.sign_with_key(&key).unwrap();
    Ok(token)
}

pub fn get_claims(app_secret: &str, token: &str) -> Result<BTreeMap<String, String>, Error> {
    let key: Hmac<Sha256> = match Hmac::new_from_slice(app_secret.as_bytes()) {
        Ok(k) => k,
        Err(_) => return Err(Error::Hmac)
    };
    match token.verify_with_key(&key) {
        Ok(claims) => Ok(claims),
        Err(e) => Err(Error::Jwt(e))
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
        
    #[test]
    fn hash_test() {
        let pass = "foo";
        let sp = create_safe_pass(pass);
        assert!(verify_pass(pass, &sp));
        assert!(!verify_pass("bar", &sp));
    }

    #[test]
    fn sign_test() {
        let app_secret = "my-secret";
        let user_id = 1;
        let jwt = sign(app_secret, user_id.to_string()).unwrap();
        let claims = get_claims(app_secret, &jwt).unwrap();
        assert_eq!(1, claims.get("id").unwrap().parse::<i32>().unwrap());

    }

}
