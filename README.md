alcoholic_jwt
=============

This is a library for **validation** of **RS256** JWTs using keys from
a JWKS. Nothing more, nothing less.

The name of the library stems from the potential side-effects of
trying to use the other Rust libraries that are made for similar
purposes.

## Usage overview

You are retrieving JWTs from some authentication provider that uses
`RS256` signatures and provides its public keys in [JWKS][] format.

Example for a token that provides the key ID used for signing in the
[`kid` claim][]:

```rust
extern crate alcoholic_jwt;

use alcoholic_jwt::{JWKS, Validation, validate, token_kid};

// The function implied here would usually perform an HTTP-GET
// on the JWKS-URL for an authentication provider and deserialize
// the result into the `alcoholic_jwt::JWKS`-struct.
let jwks: JWKS = jwks_fetching_function();

let token: String = some_token_fetching_function();

// Several types of built-in validations are provided:
let validations = vec![
  Validation::Issuer("auth.test.aprila.no".into()),
  Validation::SubjectPresent,
];

// If a JWKS contains multiple keys, the correct KID first
// needs to be fetched from the token headers.
let kid = token_kid(&token)
    .expect("Failed to decode token headers")
    .expect("No 'kid' claim present in token");

let jwk = jwks.find(&kid).expect("Specified key not found in set");

validate(token, jwk, validations).expect("Token validation has failed!");
```

## Under the hood

This library aims to only use trustworthy off-the-shelf components to
do the work. Cryptographic operations are provided by the `openssl`
crate, JSON-serialisation is provided by `serde_json`.

[JWKS]: https://tools.ietf.org/html/rfc7517
[`kid` claim]: https://tools.ietf.org/html/rfc7515#section-4.1.4
