//! Implements a library for verifying JSON Web Tokens using the
//! `RS256` signature algorithm.
//!
//! This library is specifically aimed at developers that consume
//! tokens from services which provide their RSA public keys in
//! [JWKS][] format.
//!
//! ## Usage example (token with `kid`-claim)
//!
//! ```rust
//! extern crate alcoholic_jwt;
//!
//! use alcoholic_jwt::{JWKS, Validation, validate, token_kid};
//!
//! fn validate_token() {
//!     // serde instances provided
//!     let jwks: JWKS = some_http_client(jwks_url).json();
//!
//!     let token: String = some_token_fetcher();
//!
//!     // Several types of built-in validations are provided:
//!     let validations = vec![
//!       Validation::Issuer("some-issuer"),
//!       Validation::Audience("some-audience"),
//!       Validation::SubjectPresent,
//!     ];
//!
//!     // Extracting a KID is about the only safe operation that can be
//!     // done on a JWT before validating it.
//!     let kid = token_kid(token).expect("No 'kid' claim present in token");
//!
//!     let jwk = jwks.find(kid).expect("Specified key not found in set");
//!
//!     match validate(token, jwk, validations) {
//!       Valid => println!("Token is valid!"),
//!       InvalidSignature(reason) => println!("Token signature invalid: {}", reason),
//!       InvalidClaims(reasons) => {
//!           println!("Token claims are totally invalid!");
//!           for reason in reasons {
//!               println!("Validation failure: {}", reason);
//!           }
//!       },
//!     }
//! }
//! ```
//!
//! [JWKS]: https://tools.ietf.org/html/rfc7517

#[macro_use] extern crate serde_derive;

extern crate base64;
extern crate openssl;
extern crate serde;
extern crate serde_json;

use base64::{decode_config, URL_SAFE};
use openssl::bn::BigNum;
use openssl::pkey::Public;
use openssl::rsa::{Rsa};
use openssl::error::ErrorStack;

#[cfg(test)]
mod tests;

/// JWT algorithm used. The only supported algorithm is currently
/// RS256.
#[derive(Deserialize, Debug)]
enum KeyAlgorithm { RS256 }

/// Type of key contained in a JWT. The only supported key type is
/// currently RSA.
#[derive(Deserialize, Debug)]
enum KeyType { RSA }

/// Representation of a single JSON Web Key. See [RFC
/// 7517](https://tools.ietf.org/html/rfc7517#section-4).
#[derive(Deserialize)]
pub struct JWK {
    kty: KeyType,
    alg: Option<KeyAlgorithm>,
    kid: Option<String>,

    // Shared modulus
    n: String,

    // Public key exponent
    e: String,
}

/// Representation of a collection ("set") of JSON Web Keys. See
/// [RFC 7517](https://tools.ietf.org/html/rfc7517#section-5).
pub struct JWKS {
    // This is a vector instead of some kind of map-like structure
    // because key IDs are in fact optional.
    //
    // Technically having multiple keys with the same KID would not
    // violate the JWKS-definition either, but behaviour in that case
    // is unspecified.
    keys: Vec<JWK>,
}

impl JWKS {
    /// Attempt to find a JWK by its key ID.
    pub fn find(&self, kid: &str) -> Option<&JWK> {
        self.keys.iter().find(|jwk| jwk.kid == Some(kid.into()))
    }
}

/// Representation of a JSON Web Token. See [RFC
/// 7519](https://tools.ietf.org/html/rfc7519).
pub struct JWT {}

/// Possible token claim validations. This enumeration only covers
/// common use-cases, for other types of validations the user is
/// encouraged to inspect the claim set manually.
pub enum Validation {}

/// Possible results of a token validation.
#[derive(Debug)]
pub enum ValidationError {
    /// Token was malformed (various possible reasons!)
    MalformedJWT,

    /// Decoding of the provided JWK failed.
    InvalidJWK,

    /// Signature validation failed, i.e. because of a non-matching
    /// public key.
    InvalidSignature,

    /// An OpenSSL operation failed along the way at a point at which
    /// a more specific error variant could not be constructed.
    OpenSSL(ErrorStack),

    /// One or more claim validations failed.
    // TODO: Provide reasons?
    InvalidClaims,
}

type JWTResult<T> = Result<T, ValidationError>;

impl From<ErrorStack> for ValidationError {
    fn from(err: ErrorStack) -> Self { ValidationError::OpenSSL(err) }
}

/// Attempt to extract the `kid`-claim out of a JWT's header claims.
///
/// This function is normally used when a token provider has multiple
/// public keys in rotation at the same time that could all still have
/// valid tokens issued under them.
///
/// This is only safe if the key set containing the currently allowed
/// key IDs is fetched from a trusted source.
pub fn token_kid(jwt: JWT) -> Option<String> {
    unimplemented!()
}

/// Validate the signature of a JSON Web Token and optionally apply
/// claim validations. Signatures are always verified before claims,
/// and if a signature verification passes *all* claim validations are
/// run and returned.
///
/// It is the user's task to ensure that the correct JWK is passed in
/// for validation.
pub fn validate(jwt: JWT, jwk: JWK, validations: Vec<Validation>) -> JWTResult<()> {
    unimplemented!()
}

// Internal implementation
//
// The functions in the following section are not part of the public
// API of this library.

/// Decode a single key fragment (base64-url encoded integer) to an
/// OpenSSL BigNum.
fn decode_fragment(fragment: &str) -> JWTResult<BigNum> {
    let bytes = decode_config(fragment, URL_SAFE)
        .map_err(|_| ValidationError::InvalidJWK)?;

    BigNum::from_slice(&bytes).map_err(Into::into)
}

/// Decode an RSA public key from a JWK by constructing it directly
/// from the public RSA key fragments.
fn public_key_from_jwk(jwk: &JWK) -> JWTResult<Rsa<Public>> {
    let jwk_n = decode_fragment(&jwk.n)?;
    let jwk_e = decode_fragment(&jwk.e)?;
    Rsa::from_public_components(jwk_n, jwk_e).map_err(Into::into)
}



    }
}
