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
pub enum ValidationResult {
    /// Signature and claim validation succeeded.
    Valid,

    /// Decoding of the provided JWK failed.
    InvalidJWK(String),

    /// Signature validation failed, i.e. because of a non-matching
    /// public key.
    InvalidSignature,

    /// One or more claim validations failed.
    // TODO: Provide reasons?
    InvalidClaims,
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
pub fn validate(jwt: JWT, jwk: JWK, validations: Vec<Validation>) -> ValidationResult {
    unimplemented!()
}

// Internal implementation
//
// The functions in the following section are not part of the public
// API of this library.

/// Decode a single key fragment to an OpenSSL BigNum.
fn decode_fragment(fragment: &str) -> Option<BigNum> {
    let bytes = decode_config(fragment, URL_SAFE).ok()?;
    BigNum::from_slice(&bytes).ok()
}

/// Decode an RSA public key from a JWK by constructing it directly
/// from the public RSA key fragments.
fn public_key_from_jwk(jwk: &JWK) -> Option<Rsa<Public>> {
    let jwk_n = decode_fragment(&jwk.n)?;
    let jwk_e = decode_fragment(&jwk.e)?;
    Rsa::from_public_components(jwk_n, jwk_e).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_decoding() {
        let fragment = "ngRRjNbXgPW29oNtF0JgsyyfTwPyEL0u_X16s453X2AOc33XGFxVKLEQ7R_TiMenaKcr-tPifYqgps_deyi0XOr4I3SOdOMtAVKDZJCANe--CANOHZb-meIfjKhCHisvT90fm5Apd6qPRVsXsZ7A8pmClZHKM5fwZUkBv8NsPLm2Xy2sGOZIiwP_7z8m3j0abUzniPQsx2b3xcWimB9vRtshFHN1KgPUf1ALQ5xzLfJnlFkCxC7kmOxKC7_NpQ4kJR_DKzKFV_r3HxTqf-jddHcXIrrMcLQXCSyeLQtLaz7whQ4F-EfL42z4XgwPr4ji3sct2gWL13EqlbE5DDxLKQ";
        let bignum = decode_fragment(fragment).expect("Failed to decode fragment");

        let expected = "19947781743618558124649689124245117083485690334420160711273532766920651190711502679542723943527557680293732686428091794139998732541701457212387600480039297092835433997837314251024513773285252960725418984381935183495143908023024822433135775773958512751261112853383693442999603704969543668619221464654540065497665889289271044207667765128672709218996183649696030570183970367596949687544839066873508106034650634722970893169823917299050098551447676778961773465887890052852528696684907153295689693676910831376066659456592813140662563597179711588277621736656871685099184755908108451080261403193680966083938080206832839445289";
        assert_eq!(expected, format!("{}", bignum), "Decoded fragment should match ");
    }
}
