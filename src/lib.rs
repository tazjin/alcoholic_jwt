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
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{Public, PKey};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use serde::de::DeserializeOwned;
use serde_json::Value;

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

/// Representation of a set of JSON Web Keys. See [RFC
/// 7517](https://tools.ietf.org/html/rfc7517#section-5).
#[derive(Deserialize)]
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

/// Representation of an undecoded JSON Web Token. See [RFC
/// 7519](https://tools.ietf.org/html/rfc7519).
pub struct JWT (String);

/// Representation of a decoded and validated JSON Web Token.
///
/// Specific claim fields are only decoded internally in the library
/// for validation purposes, while it is generally up to the consumer
/// of the validated JWT what structure they would like to impose.
pub struct ValidJWT {
    /// JOSE header of the JSON Web Token. Certain fields are
    /// guaranteed to be present in this header, consult section 5 of
    /// RFC7519 for more information.
    pub headers: Value,

    /// Claims (i.e. primary data) contained in the JSON Web Token.
    /// While there are several registered and recommended headers
    /// (consult section 4.1 of RFC7519), the presence of no field is
    /// guaranteed in these.
    pub claims: Value,
}

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

    /// JSON decoding into a provided type failed.
    JSON(serde_json::Error),

    /// One or more claim validations failed.
    // TODO: Provide reasons?
    InvalidClaims,
}

type JWTResult<T> = Result<T, ValidationError>;

impl From<ErrorStack> for ValidationError {
    fn from(err: ErrorStack) -> Self { ValidationError::OpenSSL(err) }
}

impl From<serde_json::Error> for ValidationError {
    fn from(err: serde_json::Error) -> Self { ValidationError::JSON(err) }
}

/// Attempt to extract the `kid`-claim out of a JWT's header claims.
///
/// This function is normally used when a token provider has multiple
/// public keys in rotation at the same time that could all still have
/// valid tokens issued under them.
///
/// This is only safe if the key set containing the currently allowed
/// key IDs is fetched from a trusted source.
pub fn token_kid(jwt: &JWT) -> JWTResult<Option<String>> {
    // Fetch the header component of the JWT by splitting it out and
    // dismissing the rest.
    let parts: Vec<&str> = jwt.0.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(ValidationError::MalformedJWT);
    }

    // Decode only the first part of the token into a specialised
    // representation:
    #[derive(Deserialize)]
    struct KidOnly {
        kid: Option<String>,
    }

    let kid_only: KidOnly = deserialize_part(parts[0])?;

    Ok(kid_only.kid)
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

/// Decode a base64-URL encoded string and deserialise the resulting
/// JSON.
fn deserialize_part<T: DeserializeOwned>(part: &str) -> JWTResult<T> {
    let json = base64::decode_config(part, URL_SAFE)
        .map_err(|_| ValidationError::MalformedJWT)?;

    serde_json::from_slice(&json).map_err(Into::into)
}

/// Validate the signature on a JWT using a provided public key.
///
/// A JWT is made up of three components (headers, claims, signature)
/// - only the first two are part of the signed data.
fn validate_jwt_signature(jwt: &JWT, key: Rsa<Public>) -> JWTResult<()> {
    let key = PKey::from_rsa(key)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;

    // Split the token from the back to a maximum of two elements.
    // There are technically three components using the same separator
    // ('.'), but we are interested in the first two together and
    // splitting them is unnecessary.
    let token_parts: Vec<&str> = jwt.0.rsplitn(2, '.').collect();
    if token_parts.len() != 2 {
        return Err(ValidationError::MalformedJWT);
    }

    // Second element of the vector will be the signed payload.
    let data = token_parts[1];

    // First element of the vector will be the (encoded) signature.
    let sig_b64 = token_parts[0];
    let sig = base64::decode_config(sig_b64, URL_SAFE)
        .map_err(|_| ValidationError::MalformedJWT)?;

    // Verify signature by inserting the payload data and checking it
    // against the decoded signature.
    verifier.update(data.as_bytes())?;

    match verifier.verify(&sig)? {
        true  => Ok(()),
        false => Err(ValidationError::InvalidSignature),
    }
}
