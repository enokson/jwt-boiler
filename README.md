# boiler-jwt

Boilerplate code for JWT token signing and decrypting.

## Add to Cargo.toml

```toml
[dependencies]
boiler-jwt = "0.1.0"
```

## JWT Signing and Verifying Example

```rust
use boiler_jwt::{to_token, from_token, to_value, from_value};

let app_secret = "my-secret";
let user_id = 1;

// create a jwt with a BTreeMap<String, Value> containing an "id" field
let jwt = to_token(app_secret, [
    ("id".into(), to_value(user_id).unwrap())
].into()).unwrap();

// convert back to a BTreeMap<String, Value>
let mut claims = from_token(app_secret, &jwt).unwrap();
assert_eq!(1, from_value::<i32>(claims.remove("id").unwrap()).unwrap());
```

## Password Hashing and Verifying Example

```rust
use boiler_jwt::{to_hash, verify};
let pass = "foo";
let hash = to_hash(pass);
assert!(verify(pass, &hash));
assert!(!verify("bar", &hash));
```
