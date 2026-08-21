package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

/**
 * Issuer encryption options / requirements for the credential request (holder sending proof to issuer)
 */
@EqualsAndHashCode(callSuper = true)
@SuperBuilder(toBuilder = true)
@Data
@Validated
@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
public class IssuerCredentialRequestEncryption extends IssuerCredentialEncryption {
    @JsonProperty("jwks")
    @Schema(description = "A JSON Web Key Set that contains one or more public keys, to be used by the Wallet as an input to a key agreement (X-Wing hybrid post-quantum KEM) for encryption of the Credential Request.", example = """
            {
              "keys" : [ {
                "kty" : "XWING",
                "kid" : "ec91e148-974d-47f1-9891-4b89d8bad57c",
                "x" : "DUQifniNCfC4WKZrG5MjThEViXWpxKyQ_gxdXao9MFvOEsAWVTi5--uLktWAcLeD30kibWQbTsYB6aVVd0asTKxtVoLLy0QC0kEUK0QXX4sZkrE65rCy6yRPzNAEPlE2LZEzukeFnnMewqSCZGOaA7KIu8Z8grFsSYEWFOAA3wl_TZiG1vNaqiVw2gRfawE08FqAgyquc1ZCwRVdclxryycNGMC7XbwWTAcdnlGMR1E2KHqTLWOkayBym-XB2tGPHxFW_eFOy8q_RbAKSYNL1tEnMXNQADlsxGaIPjZjekK2MrpItDOSa5Qi-0Uwe-WwoenHdiQg7RYQsopNzWyigoabDcQSJCK2C1sJQMmEZQIq1VjB3DC6rcBleLwnYBJXi5CUUQaZeHqmSWOhamVANwDGC3e0k_NDE3cIaMCx76N7G1l1dBCGd3fMb9pjo3Uvl4TGYjmbVZR-EFwkoGU108k3jAmNRziR9yFrJhVhldIDC8Bzx0y6sPSQ8VAY6pg8yqe7KlbJsyUBL1cf1vegHNwWADdpkAUbYxZsnKAc3UVdSAM_lOwPMIBvrMNtqZQusUQbcoM625otFbUNVJCgDIx2MATN08BJo8m_F8PLzRHFMZp5CmV_J0fM5FEIYyCR9Kk7nnp3uidXm1IeTaZAX3C7PZZ29xaIs6vKaQKiEzZy13ldW7CFr7UdbALM7oxpIxRFd9DAwqNIzrYX8YI_winLKFpE6glVNAyZg2VWK9oggmNjDKdFFBQFj-AAjdBbgSwer_qUnxKhx6FX2QJq63F_qSNwjncox5OXS3OY_TcFsmu9yTIVJkADp3mXJRBzl7Z7B8HKLlxiyaqIUnmWnuccsKzKELFFRtjIR4IvxYoHTQuJI2EGBTdFFNGxk3dxVqSywBOGnItxkPlYQXyvFbbIFTuzPmSV0OGr_lhoFyWG0CKtitGyF3YIjReuCvJFCbC4oQVmZHC-JWCfxTYrxOp-_PTBicSaz5jEsLJUuLyV1tyXQemNqTS9tKNfXUbGOwt35WEajxOUE4GVDvYD8sNX_4An4CQ2_7yWExAovJCbQHR4DBVTLvI6DOg9S6BiLEpsAlInMKBoIRu8wbA-cdujvQyKtHm1hLKUQYdrgLCgT_HLxmKO54YUUIK8QxGYP5F6VGygPPMrbfBg7Tqcnkd9IOUqIdNY6mspiiO_Y8tL8EeJJJIxUxgv-VEBcgFm_3ZU5kaJLxozoNNSwZk-vwN6bgaXdFJorzpO3dRnKeyBVtE47ACBVLEC5xlq_wGdr2KIDYeeUVQkgdxtySt1KHO7gPQDxlBnv7Yl3za5dsCVUyC0X9QPIfSLFLKRowWdtVCdQ2M_cLyG8GmuIdtOHKDBr4eThPJRWeGOcDc4lyN4qBKFqTCMQ0qoS_GgDEqm7SCVEiYsNSprWLO_LKea6sEJGnRFG4p64CUO6IimpvueyeKoJVeRoOqd6muV4LWI3bUA81xW4-sbYHweihURItcIGXCDBFeWtJQkG8CeRtVNSFZ70oRC4ZICOvOllDlOyE3Ls0Hi-jmYcSLXe_CBFn7XuVLNwOew3YwgUgcVhiuxXBZkN7pYs3f9E79i_dTCXxR9F-2rHwo73waSAIKADQ"
              } ]
            }
            """)
    private Map<String, Object> jwks;


}
