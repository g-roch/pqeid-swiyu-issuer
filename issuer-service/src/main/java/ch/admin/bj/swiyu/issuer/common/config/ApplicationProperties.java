package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Validated
@Data
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    @NotNull
    private String externalUrl;

    @NotEmpty
    private String deeplinkSchema;

    @NotNull
    private String issuerId;

    @NotNull
    private Long offerValidity;

    @NotNull
    private Integer deferredOfferValiditySeconds;

    @NotNull
    @Min(value = 5, message = "Minimal deferred offer interval must be at least 5 seconds")
    private Long minDeferredOfferIntervalSeconds;

    /**
     * List of DIDs of Attestation Providers deemed trustworthy for verifying the Key Attestation.
     */
    @NotNull
    private List<String> trustedAttestationProviders;

     // PQEID: JWS algorithms accepted for signatures verified against DID keys (key attestations,
    // data integrity). Holder proofs use the per-credential proof_signing_alg_values_supported instead.
    @NotEmpty
    private List<String> acceptedSignatureAlgorithms = List.of("ML-DSA-44", "ML-DSA-65-ES256");

    /** The policy as nimbus algorithms (not a JavaBean getter, so Spring doesn't try to bind it). */
    public Set<JWSAlgorithm> acceptedSignatureJwsAlgorithms() {
        return acceptedSignatureAlgorithms.stream()
                .map(JWSAlgorithm::parse)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * If set to true the service expects all
     * writing message bodies to be encoded as JWT
     */
    @NotNull
    private boolean enableJwtAuthentication;

    /**
     * Flag to enable the storage of hashes of *each* VC signed by the generic issuer.
     * This is the JWS of the SD-JWT VC
     */
    @NotNull
    private boolean enableVcHashStorage;

    /**
     * If enableJWTAuthentication is set,
     * the JWTs will be checked against the public keys
     * stored in this json web key set.
     * Is expected to be a map with the key "keys"
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">Example
     * how the JWKS is expected</a>
     */
    private String authenticationJwks;

    private JWKSet allowedKeySet;

    @NotNull
    private Map<String, String> templateReplacement;
    @Nullable
    private Map<String, String> vctMetadataFiles;
    @Nullable
    private Map<String, String> jsonSchemaMetadataFiles;
    @Nullable
    private Map<String, String> overlaysCaptureArchitectureMetadataFiles;

    @NotNull
    private long tokenTTL;

    /**
     * Flag Indicating if refresh tokens are used
     */
    @NotNull
    private boolean allowTokenRefresh;
    /**
     * Flag indicating if refresh tokens are changed after use
     */
    @NotNull
    private boolean allowRefreshTokenRotation;

    @NotNull
    private boolean renewalFlowAllowed;

    private String businessIssuerRenewalApiEndpoint;

    @NotNull
    private int acceptableProofTimeWindowSeconds;
    @NotNull
    private int nonceLifetimeSeconds;
    @NotNull
    private Duration encryptionKeyRotationInterval;
    private boolean encryptionEnforce;

    private boolean dpopEnforce;

    private boolean automaticStatusListSynchronizationDisabled;

    private String dataIntegrityJwks;
    private JWKSet dataIntegrityKeySet;
    private boolean dataIntegrityEnforced;
    private boolean signedMetadataEnabled;

    /**
     * If set to true, Swiss Profile version indications (profile_version) will be enforced where applicable.
     * Default is false to allow a transitional period.
     */
    private boolean swissProfileVersioningEnforcement = false;

    @PostConstruct
    public void init() {
        try {
            if (enableJwtAuthentication) {
                allowedKeySet = JWKSet.parse(authenticationJwks);
            }
            if (StringUtils.isNotBlank(dataIntegrityJwks)) {
                dataIntegrityKeySet = JWKSet.parse(dataIntegrityJwks);
            }
        } catch (ParseException e) {
            log.error("Provided Allow JWKSet can not be parsed! %s".formatted(authenticationJwks));
            throw new ConfigurationException(
                    "Provided Allow JWKSet can not be parsed! %s".formatted(authenticationJwks));
        }
    }

    public boolean isRenewalFlowEnabled() {
        return this.isDpopEnforce() && this.isRenewalFlowAllowed() && this.getBusinessIssuerRenewalApiEndpoint() != null;
    }
}