package ch.admin.bj.swiyu.issuer.util;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class DemonstratingProofOfPossessionTestUtil {
    private static final MessageDigest sha256 = assertDoesNotThrow(() -> MessageDigest.getInstance("SHA-256"));

    // DPoP JWTs are validated by swiyu-dpop-util's DpopJwtValidator.validateAlgorithm()
    // against DpopConstants.SUPPORTED_ALGORITHMS, which is ML-DSA-44 only (no ES256
    // fallback) - see swiyu-generic-java-lib.
    public static String createDPoPJWT(String httpMethod, String httpUri, String accessToken, MLDSAKey dpopKey, String dpopNonce) {
        var claimSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .claim("htm", httpMethod)
                .claim("htu", httpUri)
                .claim("nonce", dpopNonce);
        if (StringUtils.isNotEmpty(accessToken)) {
            claimSetBuilder.claim("ath", createSha256Hash(accessToken));
        }
        var signedJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44)
                .jwk(dpopKey.toPublicJWK())
                .type(new JOSEObjectType("dpop+jwt"))
                .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build(),
                claimSetBuilder.build());
        assertDoesNotThrow(() -> signedJwt.sign(new MLDSASigner(dpopKey)));
        return signedJwt.serialize();
    }

    private static String createSha256Hash(String accessToken) {
        return Base64.getUrlEncoder().encodeToString(sha256.digest(accessToken.getBytes(StandardCharsets.UTF_8)));
    }
}
