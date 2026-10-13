package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListToken;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSInput;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link StatusListSigningService}.
 */
class StatusListSigningServiceTest {

    private ApplicationProperties applicationProperties;
    private StatusListProperties statusListProperties;
    private JwsSignatureFacade jwsSignatureFacade;
    private StatusListSigningService sut;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        statusListProperties = mock(StatusListProperties.class);
        jwsSignatureFacade = mock(JwsSignatureFacade.class);

        when(applicationProperties.getIssuerId()).thenReturn("did:example:issuer");
        when(statusListProperties.getVerificationMethod()).thenReturn("did:example:vm#1");

        sut = new StatusListSigningService(applicationProperties, statusListProperties, jwsSignatureFacade);
    }

    @Test
    void buildSignedStatusListJwt_successfulSigning_returnsSignedJwt() throws Exception {
        // Arrange
        var statusList = StatusList.builder()
                .uri("https://registry.example/status/uuid-1234")
                .configurationOverride(new ConfigurationOverride(null, "did:example:vm#override", null, null))
                .build();

        TokenStatusListToken token = new TokenStatusListToken(2, 8);

        // Use a real ML-DSA-44 signer to exercise Nimbus signing flow
        JWSSigner signer = createDummySigner();
        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenReturn(signer);

        // Act
        SignedJWT signed = sut.buildSignedStatusListJwt(statusList, token);

        // Assert
        assertNotNull(signed);

        // Verify header values
        JWSHeader header = signed.getHeader();
        assertEquals("statuslist+jwt", header.getType().getType());
        assertEquals(SwissProfileVersions.VC_PROFILE_VERSION, header.getCustomParam(SwissProfileVersions.PROFILE_VERSION_PARAM));

        // Verify claims
        var claims = signed.getJWTClaimsSet();
        assertEquals(applicationProperties.getIssuerId(), claims.getIssuer());
        assertEquals(statusList.getUri(), claims.getSubject());
        assertEquals(statusListProperties.getStatusListCacheTime().toSeconds(), ((Number) claims.getClaim("ttl")).intValue());
        assertNotNull(claims.getClaim("status_list"));
        assertTrue(((Map<?, ?>) claims.getClaim("status_list")).containsKey("bits"));
        assertTrue(((Map<?, ?>) claims.getClaim("status_list")).containsKey("lst"));
    }

    @Test
    void buildSignedStatusListJwt_throwsConfigurationException_onKeyStrategyError() throws KeyStrategyException {
        // Arrange
        var statusList = StatusList.builder().uri("https://registry.example/status/1").build();
        TokenStatusListToken token = new TokenStatusListToken(1, 4);

        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenThrow(new KeyStrategyException("bad", null));

        // Act / Assert
        assertThrows(ConfigurationException.class, () -> sut.buildSignedStatusListJwt(statusList, token));
    }

    @Test
    void buildSignedStatusListJwt_throwsConfigurationException_onJoseException() throws Exception {
        // Arrange
        var statusList = StatusList.builder().uri("https://registry.example/status/2").build();
        TokenStatusListToken token = new TokenStatusListToken(1, 4);

        JWSSigner failingSigner = mock(JWSSigner.class);
        // PQEID: the header alg is derived from the signer, so the mock must declare one
        when(failingSigner.supportedJWSAlgorithms()).thenReturn(java.util.Set.of(JWSAlgorithm.ML_DSA_44));
        when(failingSigner.sign(any(), any(JWSInput.class))).thenThrow(new JOSEException("simulated signing failure"));
        when(jwsSignatureFacade.createSigner(statusListProperties, null, null)).thenReturn(failingSigner);

        // Act / Assert
        assertThrows(ConfigurationException.class, () -> sut.buildSignedStatusListJwt(statusList, token));
    }

    @Test
    void buildSignedStatusListJwt_compositeKey_headerAlgFollowsKey() throws Exception {
        // Arrange
        java.security.Security.addProvider(
                com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
        var kp = java.security.KeyPairGenerator
                .getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        var key = com.nimbusds.jose.jwk.CompositeMLDSAKey.fromJCA(kp.getPublic(), kp.getPrivate());
        when(jwsSignatureFacade.createSigner(statusListProperties, null, null))
                .thenReturn(new com.nimbusds.jose.crypto.CompositeSigner(key));
        var statusList = StatusList.builder().uri("https://registry.example/status/c").build();

        SignedJWT signed = sut.buildSignedStatusListJwt(statusList, new TokenStatusListToken(1, 4));

        // Act / Assert
        assertEquals(JWSAlgorithm.ML_DSA_65_ES256, signed.getHeader().getAlgorithm());
        assertTrue(signed.verify(new com.nimbusds.jose.crypto.CompositeVerifier(key.toPublicJWK())));
    }

    private JWSSigner createDummySigner() throws JOSEException {
        MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44)
                .keyID("test-key")
                .generate();
        return new MLDSASigner(mldsaJWK);
    }
}

