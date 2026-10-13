package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.jwtutil.SignatureVerifiers;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.CompositeSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** PQEID: signed management requests are verified through the issuer policy. */
class JWTResolveRequestWrapperTest {

    @BeforeAll
    static void registerBc() {
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    /** A POST whose body is a JWT with claim data={"x":1}, signed by {@code signer} under {@code key}'s kid/alg. */
    private static MockHttpServletRequest signedRequest(JWK key, JWSSigner signer) throws Exception {
        var jwt = new SignedJWT(
                new JWSHeader.Builder((JWSAlgorithm) key.getAlgorithm()).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().claim("data", "{\"x\":1}").build());
        jwt.sign(signer);
        var request = new MockHttpServletRequest("POST", "/management/api/credentials");
        request.setContent(jwt.serialize().getBytes(StandardCharsets.UTF_8));
        return request;
    }

    @Test
    void compositeSignedRequest_isAccepted_andDataExtracted() throws Exception {
        // Arrange
        var kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        CompositeMLDSAKey key = CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate(), "mgmt-key");
        var request = signedRequest(key, new CompositeSigner(key));

        // Act
        var wrapper = JWTResolveRequestWrapper.createAndValidate(request, new JWKSet(key.toPublicJWK()),
                SignatureVerifiers.MIGRATION_DEFAULT);

        // Assert
        assertEquals("{\"x\":1}", wrapper.getDataClaim());
    }

    @Test
    void mldsa44Request_underContractPolicy_isRejected() throws Exception {
        // Arrange
        MLDSAKey key = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("mgmt-key").generate();
        var request = signedRequest(key, new MLDSASigner(key));

        // Act / Assert
        assertThrows(BadRequestException.class, () -> JWTResolveRequestWrapper.createAndValidate(
                request, new JWKSet(key.toPublicJWK()), Set.of(JWSAlgorithm.ML_DSA_65_ES256)));
    }

    @Test
    void requestSignedWithUnknownKey_isRejected() throws Exception {
        // Arrange: signed by A, only B is allowed (same kid, so the check is the signature)
        MLDSAKey a = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("mgmt-key").generate();
        MLDSAKey b = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("mgmt-key").generate();
        var request = signedRequest(a, new MLDSASigner(a));

        // Act / Assert
        assertThrows(BadRequestException.class, () -> JWTResolveRequestWrapper.createAndValidate(
                request, new JWKSet(b.toPublicJWK()), SignatureVerifiers.MIGRATION_DEFAULT));
    }
}
