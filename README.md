alcoholic_jwt
=============

This is a barebones library for **validation** of **RS256** JWTs using
keys from a JWKS. Nothing more, nothing less.

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

fn validate_token() {
    // serde instances provided
    let jwks: JWKS = some_http_client(jwks_url).json();

    let token: String = some_token_fetcher();

    // Several types of built-in validations are provided:
    let validations = vec![
      Validation::Issuer("some-issuer"),
      Validation::Audience("some-audience"),
      Validation::SubjectPresent,
    ];

    // Extracting a KID is about the only safe operation that can be
    // done on a JWT before validating it.
    let kid = token_kid(token).expect("No 'kid' claim present in token");

    let jwk = jwks.find(kid).expect("Specified key not found in set");

    match validate(token, jwk, validations) {
      Valid => println!("Token is valid!"),
      InvalidSignature(reason) => println!("Token signature invalid: {}", reason),
      InvalidClaims(reasons) => {
          println!("Token claims are totally invalid!");
          for reason in reasons {
              println!("Validation failure: {}", reason);
          }
      },
    }
}
```

## Under the hood

This library aims to only use trustworthy off-the-shelf components to
do the work. Cryptographic operations are provided by the `openssl`
crate, JSON-serialisation is provided by `serde_json`.

[JWKS]: https://tools.ietf.org/html/rfc7517
[`kid` claim]: https://tools.ietf.org/html/rfc7515#section-4.1.4
