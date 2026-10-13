package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** PQEID: the issuer's metadata may advertise the composite ML-DSA-65-ES256 (signing and holder proofs). */
class SigningAlgorithmMetadataValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-DSA-65-ES256"})
    void acceptedAlgorithms_areValid(String alg) {
        var proof = SupportedProofType.builder().supportedSigningAlgorithms(List.of(alg)).build();
        var config = CredentialConfiguration.builder().credentialSigningAlgorithmsSupported(List.of(alg)).build();

        assertThat(validator.validateProperty(proof, "supportedSigningAlgorithms")).isEmpty();
        assertThat(validator.validateProperty(config, "credentialSigningAlgorithmsSupported")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ML-DSA-65-ES999", "ml-dsa-65-es256"})
    void otherAlgorithms_areRejected(String alg) {
        var proof = SupportedProofType.builder().supportedSigningAlgorithms(List.of(alg)).build();
        var config = CredentialConfiguration.builder().credentialSigningAlgorithmsSupported(List.of(alg)).build();

        assertThat(validator.validateProperty(proof, "supportedSigningAlgorithms")).isNotEmpty();
        assertThat(validator.validateProperty(config, "credentialSigningAlgorithmsSupported")).isNotEmpty();
    }
}