use super::*;

#[test]
fn test_fragment_decoding() {
    let fragment = "ngRRjNbXgPW29oNtF0JgsyyfTwPyEL0u_X16s453X2AOc33XGFxVKLEQ7R_TiMenaKcr-tPifYqgps_deyi0XOr4I3SOdOMtAVKDZJCANe--CANOHZb-meIfjKhCHisvT90fm5Apd6qPRVsXsZ7A8pmClZHKM5fwZUkBv8NsPLm2Xy2sGOZIiwP_7z8m3j0abUzniPQsx2b3xcWimB9vRtshFHN1KgPUf1ALQ5xzLfJnlFkCxC7kmOxKC7_NpQ4kJR_DKzKFV_r3HxTqf-jddHcXIrrMcLQXCSyeLQtLaz7whQ4F-EfL42z4XgwPr4ji3sct2gWL13EqlbE5DDxLKQ";
    let bignum = decode_fragment(fragment).expect("Failed to decode fragment");

    let expected = "19947781743618558124649689124245117083485690334420160711273532766920651190711502679542723943527557680293732686428091794139998732541701457212387600480039297092835433997837314251024513773285252960725418984381935183495143908023024822433135775773958512751261112853383693442999603704969543668619221464654540065497665889289271044207667765128672709218996183649696030570183970367596949687544839066873508106034650634722970893169823917299050098551447676778961773465887890052852528696684907153295689693676910831376066659456592813140662563597179711588277621736656871685099184755908108451080261403193680966083938080206832839445289";
    assert_eq!(expected, format!("{}", bignum), "Decoded fragment should match ");
}

#[test]
fn test_decode_find_jwks() {
    let json = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"mUjI\\/rIMLLtung35BKZfdbrqtlEAAYJ4JX\\/SKvnLxJc=\",\"n\":\"ngRRjNbXgPW29oNtF0JgsyyfTwPyEL0u_X16s453X2AOc33XGFxVKLEQ7R_TiMenaKcr-tPifYqgps_deyi0XOr4I3SOdOMtAVKDZJCANe--CANOHZb-meIfjKhCHisvT90fm5Apd6qPRVsXsZ7A8pmClZHKM5fwZUkBv8NsPLm2Xy2sGOZIiwP_7z8m3j0abUzniPQsx2b3xcWimB9vRtshFHN1KgPUf1ALQ5xzLfJnlFkCxC7kmOxKC7_NpQ4kJR_DKzKFV_r3HxTqf-jddHcXIrrMcLQXCSyeLQtLaz7whQ4F-EfL42z4XgwPr4ji3sct2gWL13EqlbE5DDxLKQ\",\"e\":\"GK7oLCDbNPAF59LhvyseqcG04hDnPs58qGYolr_HHmaR4lulWJ90ozx6e4Ut363yKG2p9vwvivR5UIC-aLPtqT2qr-OtjhBFzUFVaMGZ6mPCvMKk0AgMYdOHvWTgBSqQtNJTvl1yYLnhcWyoE2fLQhoEbY9qUyCBCEOScXOZRDpnmBtz5I8q5yYMV6a920J24T_IYbxHgkGcEU2SGg-b1cOMD7Rja7vCfV---CQ2pR4leQ0jufzudDoe7z3mziJm-Ihcdrz2Ujy5kPEMdz6R55prJ-ENKrkD_X4u5aSlSRaetwmHS3oAVkjr1JwUNbqnpM-kOqieqHEp8LUmez-Znw\"}]}";
    let jwks: JWKS = serde_json::from_str(json).expect("Failed to decode JWKS");
    let jwk = jwks.find("mUjI/rIMLLtung35BKZfdbrqtlEAAYJ4JX/SKvnLxJc=")
        .expect("Failed to find required JWK");

    public_key_from_jwk(&jwk).expect("Failed to construct public key from JWK");
}

#[test]
fn test_token_kid() {
    let jwt = JWT("eyJraWQiOiI4ckRxOFB3MEZaY2FvWFdURVZRbzcrVGYyWXpTTDFmQnhOS1BDZWJhYWk0PSIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoLnRlc3QuYXByaWxhLm5vIiwiaWF0IjoxNTM2MDUwNjkzLCJleHAiOjE1MzYwNTQyOTMsInN1YiI6IjQyIiwiZXh0Ijoic21va2V0ZXN0IiwicHJ2IjoiYXJpc3RpIiwic2NwIjoicHJvY2VzcyJ9.gOLsv98109qLkmRK6Dn7WWRHLW7o8W78WZcWvFZoxPLzVO0qvRXXRLYc9h5chpfvcWreLZ4f1cOdvxv31_qnCRSQQPOeQ7r7hj_sPEDzhKjk-q2aoNHaGGJg1vabI--9EFkFsGQfoS7UbMMssS44dgR68XEnKtjn0Vys-Vzbvz_CBSCH6yQhRLik2SU2jR2L7BoFvh4LGZ6EKoQWzm8Z-CHXLGLUs4Hp5aPhF46dGzgAzwlPFW4t9G4DciX1uB4vv1XnfTc5wqJch6ltjKMde1GZwLR757a8dJSBcmGWze3UNE2YH_VLD7NCwH2kkqr3gh8rn7lWKG4AUIYPxsw9CB".into());

    let kid = token_kid(&jwt).expect("Failed to extract token KID");
    assert_eq!(Some("8rDq8Pw0FZcaoXWTEVQo7+Tf2YzSL1fBxNKPCebaai4=".into()),
               kid, "Extracted KID did not match expected KID");
}

#[test]
fn test_validate_jwt() {
    let jwks_json = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"8rDq8Pw0FZcaoXWTEVQo7+Tf2YzSL1fBxNKPCebaai4=\",\"n\":\"l4UTgk1zr-8C8utt0E57DtBV6qqAPWzVRrIuQS2j0_hp2CviaNl5XzGRDnB8gwk0Hx95YOhJupAe6RNq5ok3fDdxL7DLvppJNRLz3Ag9CsmDLcbXgNEQys33fBJaPw1v3GcaFC4tisU5p-o1f5RfWwvwdBtdBfGiwT1GRvbc5sFx6M4iYjg9uv1lNKW60PqSJW4iDYrfqzZmB0zF1SJ0BL_rnQZ1Wi_UkFmNe9arM8W9tI9T3Ie59HITFuyVSTCt6qQEtSfa1e5PiBaVuV3qoFI2jPBiVZQ6LPGBWEDyz4QtrHLdECPPoTF30NN6TSVwwlRbCuUUrdNdXdjYe2dMFQ\",\"e\":\"DhaD5zC7mzaDvHO192wKT_9sfsVmdy8w8T8C9VG17_b1jG2srd3cmc6Ycw-0blDf53Wrpi9-KGZXKHX6_uIuJK249WhkP7N1SHrTJxO0sUJ8AhK482PLF09Qtu6cUfJqY1X1y1S2vACJZItU4Vjr3YAfiVGQXeA8frAf7Sm4O1CBStCyg6yCcIbGojII0jfh2vSB-GD9ok1F69Nmk-R-bClyqMCV_Oq-5a0gqClVS8pDyGYMgKTww2RHgZaFSUcG13KeLMQsG2UOB2OjSC8FkOXK00NBlAjU3d0Vv-IamaLIszO7FQBY3Oh0uxNOvIE9ofQyCOpB-xIK6V9CTTphxw\"}]}";

    let jwks: JWKS = serde_json::from_str(jwks_json)
        .expect("Failed to decode JWKS");

    let jwk = jwks.find("8rDq8Pw0FZcaoXWTEVQo7+Tf2YzSL1fBxNKPCebaai4=")
        .expect("Failed to find required JWK");

    let pkey = public_key_from_jwk(&jwk).expect("Failed to construct public key");

    let jwt = JWT("eyJraWQiOiI4ckRxOFB3MEZaY2FvWFdURVZRbzcrVGYyWXpTTDFmQnhOS1BDZWJhYWk0PSIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoLnRlc3QuYXByaWxhLm5vIiwiaWF0IjoxNTM2MDUwNjkzLCJleHAiOjE1MzYwNTQyOTMsInN1YiI6IjQyIiwiZXh0Ijoic21va2V0ZXN0IiwicHJ2IjoiYXJpc3RpIiwic2NwIjoicHJvY2VzcyJ9.gOLsv98109qLkmRK6Dn7WWRHLW7o8W78WZcWvFZoxPLzVO0qvRXXRLYc9h5chpfvcWreLZ4f1cOdvxv31_qnCRSQQPOeQ7r7hj_sPEDzhKjk-q2aoNHaGGJg1vabI--9EFkFsGQfoS7UbMMssS44dgR68XEnKtjn0Vys-Vzbvz_CBSCH6yQhRLik2SU2jR2L7BoFvh4LGZ6EKoQWzm8Z-CHXLGLUs4Hp5aPhF46dGzgAzwlPFW4t9G4DciX1uB4vv1XnfTc5wqJch6ltjKMde1GZwLR757a8dJSBcmGWze3UNE2YH_VLD7NCwH2kkqr3gh8rn7lWKG4AUIYPxsw9CB".into());

    validate_jwt_signature(&jwt, pkey).expect("Validation failed unexpectedly");
}
