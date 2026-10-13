package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for shared abstract signing key verification health checker logic.
 */
class SigningKeyVerificationHealthCheckerTest {

    private KeyResolver keyResolver;
    private JwsSignatureFacade jwsSignatureFacade;
    private SdjwtProperties properties;
    private ApplicationProperties applicationProperties;

    // Concrete minimal subclass to expose performCheck
    private static class TestChecker extends AbstractSigningKeyVerificationHealthChecker<SdjwtProperties> {
        protected TestChecker(KeyResolver keyResolver, JwsSignatureFacade jwsSignatureFacade, SdjwtProperties properties,
                              ApplicationProperties applicationProperties) {
            super(keyResolver, jwsSignatureFacade, properties, applicationProperties);
        }
    }

    @BeforeEach
    void setup() throws JOSEException, KeyStrategyException, ParseException {
        keyResolver = Mockito.mock(KeyResolver.class);
        jwsSignatureFacade = Mockito.mock(JwsSignatureFacade.class);
        properties = new SdjwtProperties();
        properties.setVerificationMethod("did:example:123#key-1");
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        when(applicationProperties.acceptedSignatureJwsAlgorithms())
                .thenReturn(ch.admin.bj.swiyu.jwtutil.SignatureVerifiers.MIGRATION_DEFAULT);

        // Provide a mock JWK for DID resolution (public ML-DSA key). This mocks KeyResolver
        // directly (a Java JWK in, JWK out interface) rather than going through a real
        // did_sidekicks Rust Jwk struct, so it does not hit the known EC-only DID-resolution
        // blocker (see AbstractSigningKeyVerificationHealthChecker.verifySignature()).
        var mldsaKey = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("test-key").generate();
        when(keyResolver.resolveKey("did:example:123#key-1")).thenReturn(JWK.parse(mldsaKey.toPublicJWK().toJSONString()));

        // Provide a signer that can sign ML-DSA-44
        JWSSigner signer = new MLDSASigner(mldsaKey);
        when(jwsSignatureFacade.createSigner(any(), any(), any())).thenReturn(signer);
    }

    @Test
    void performCheck_successfulVerification_setsUpStatus() {
        var checker = new TestChecker(keyResolver, jwsSignatureFacade, properties, applicationProperties);
        Health.Builder builder = Health.up(); // initial state, will be overridden
        checker.performCheck(builder);
        var result = builder.build();
        assertEquals(Status.UP, result.getStatus());
        assertTrue(result.getDetails().containsKey("signingKeyVerificationMethod"));
        assertEquals("did:example:123#key-1", result.getDetails().get("signingKeyVerificationMethod"));
    }

    @Test
    void performCheck_failedDidResolution_setsDownStatus() {
        properties.setVerificationMethod("did:example:unknown#k1");
        when(keyResolver.resolveKey("did:example:unknown#k1")).thenReturn(null); // simulate failure
        var checker = new TestChecker(keyResolver, jwsSignatureFacade, properties, applicationProperties);
        Health.Builder builder = Health.up();
        checker.performCheck(builder);
        var result = builder.build();
        assertEquals(Status.DOWN, result.getStatus());
        assertTrue(result.getDetails().containsKey("failedDids"));
        assertEquals("did:example:unknown#k1", result.getDetails().get("failedDids"));
    }

    @Test
    void performCheck_compositeKey_setsUpStatus() throws Exception {
        // Arrange
        java.security.Security.addProvider(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
        var kp = java.security.KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        var key = com.nimbusds.jose.jwk.CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
        when(keyResolver.resolveKey("did:example:123#key-1")).thenReturn(key.toPublicJWK());
        when(jwsSignatureFacade.createSigner(any(), any(), any()))
                .thenReturn(new com.nimbusds.jose.crypto.CompositeSigner(key));
        var checker = new TestChecker(keyResolver, jwsSignatureFacade, properties, applicationProperties);

        // Act
        Health.Builder builder = Health.up();
        checker.performCheck(builder);

        // Assert
        assertEquals(Status.UP, builder.build().getStatus());
    }

    @Test
    void performCheck_keyOutsidePolicy_setsDownStatus() {
        // Arrange: the setup's ML-DSA-44 key, but a composite-only (contract) policy
        when(applicationProperties.acceptedSignatureJwsAlgorithms())
                .thenReturn(java.util.Set.of(JWSAlgorithm.ML_DSA_65_ES256));
        var checker = new TestChecker(keyResolver, jwsSignatureFacade, properties, applicationProperties);

        // Act
        Health.Builder builder = Health.up();
        checker.performCheck(builder);

        // Assert
        assertEquals(Status.DOWN, builder.build().getStatus());
    }
}

