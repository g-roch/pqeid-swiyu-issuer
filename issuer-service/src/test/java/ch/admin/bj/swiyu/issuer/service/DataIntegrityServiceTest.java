package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// DataIntegrityService.verifyDataIntegrityJWT() delegates to swiyu-jwt-util's
// JwtUtil.verifyJwt(), whose VERIFIER_FACTORIES map only has an entry for KeyType.AKP
// (ML-DSA) - so these test JWTs must be signed with ML-DSA-44.
class DataIntegrityServiceTest {

    private static MLDSAKey mldsaKey = null;
    private DataIntegrityService dataIntegrityService;
    private ApplicationProperties applicationProperties;
    private ObjectMapper objectMapper;

    @BeforeAll
    static void init() throws JOSEException {
        mldsaKey = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("123").generate();
    }

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        applicationProperties = mock(ApplicationProperties.class);
        when(applicationProperties.getDataIntegrityKeySet()).thenReturn(new JWKSet(mldsaKey.toPublicJWK()));
        when(applicationProperties.acceptedSignatureJwsAlgorithms())
                .thenReturn(ch.admin.bj.swiyu.jwtutil.SignatureVerifiers.MIGRATION_DEFAULT);

        dataIntegrityService = new DataIntegrityService(applicationProperties, objectMapper);
    }

    @Test
    void testMissingData_thenFailure() {
        var exception = Assertions.assertThrows(BadRequestException.class, () -> dataIntegrityService.getVerifiedOfferData(null, null));
        Assertions.assertEquals("No offer data found", exception.getMessage());
    }

    @Test
    void testUnsignedData_thenSuccess() {
        Map<String, Object> offerData = getTestData();
        when(applicationProperties.isDataIntegrityEnforced()).thenReturn(false);
        var unpackedData = Assertions.assertDoesNotThrow(() -> dataIntegrityService.getVerifiedOfferData(wrapTestData(offerData), null));
        Assertions.assertTrue(offerData.keySet().containsAll(unpackedData.keySet()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testMissingSignatureData_whenEnforced_thenFailure(boolean informDataIntegrity) throws JsonProcessingException {
        var offerData = wrapTestData(getTestData());
        if (informDataIntegrity) {
            offerData.put("data_integrity", "jwt");
        }
        when(applicationProperties.isDataIntegrityEnforced()).thenReturn(true);
        var exception = Assertions.assertThrows(BadRequestException.class, () -> dataIntegrityService.getVerifiedOfferData(offerData, null));
        Assertions.assertEquals("Failed to parse JWT", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testSignedData_whenEnforced_thenSuccess(boolean informDataIntegrity) throws ParseException, JOSEException {
        var offerData = getTestData();
        var wrappedData = wrapTestDataSigned(offerData, mldsaKey);
        if (informDataIntegrity) {
            wrappedData.put("data_integrity", "jwt");
        }
        when(applicationProperties.isDataIntegrityEnforced()).thenReturn(true);
        var unpackedData = Assertions.assertDoesNotThrow(() -> dataIntegrityService.getVerifiedOfferData(wrappedData, null));
        Assertions.assertTrue(offerData.keySet().containsAll(unpackedData.keySet()));
    }

    private Map<String, Object> getTestData() {
        return Map.of("hello", 1, "world", 2);
    }

    private Map<String, Object> wrapTestData(Map<String, Object> data) throws JsonProcessingException {
        Map<String, Object> wrapped = new HashMap<>();
        wrapped.put("data", objectMapper.writeValueAsString(data));
        return wrapped;
    }

    private Map<String, Object> wrapTestDataSigned(Map<String, Object> data, MLDSAKey key) throws ParseException, JOSEException {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44).keyID(key.getKeyID()).build(), JWTClaimsSet.parse(data));
        jwt.sign(new MLDSASigner(key));
        Map<String, Object> wrapped = new HashMap<>();
        wrapped.put("data", jwt.serialize());
        return wrapped;
    }
}
