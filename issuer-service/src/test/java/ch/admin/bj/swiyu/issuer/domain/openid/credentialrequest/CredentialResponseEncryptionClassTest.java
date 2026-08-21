package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.XWingKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CredentialResponseEncryptionClassTest {

    @Test
    void whenConstructingWitValidKey_thenSuccess() {
        var key = assertDoesNotThrow(() -> new XWingKeyGenerator().keyID("TestKey").algorithm(JWEAlgorithm.XWING).keyUse(KeyUse.ENCRYPTION).generate());
        var keyJson = key.toPublicJWK().toJSONObject();
        var credentialResponseEncryption = assertDoesNotThrow(() -> new CredentialResponseEncryptionClass(keyJson, EncryptionMethod.A256GCM.getName()));
        assertDoesNotThrow(credentialResponseEncryption::extractAlg);
        assertDoesNotThrow(credentialResponseEncryption::getEnc);
    }

    @Test
    void whenMissingAlg_thenThrowsOid4vcException() {
        var key = assertDoesNotThrow(() -> new XWingKeyGenerator().keyID("TestKey").keyUse(KeyUse.ENCRYPTION).generate());
        var keyJson = key.toPublicJWK().toJSONObject();
        var responseEncryption = assertDoesNotThrow(() -> new CredentialResponseEncryptionClass(keyJson, EncryptionMethod.A256GCM.getName()));
        assertThrows(Oid4vcException.class, () -> responseEncryption.extractAlg());
    }

}