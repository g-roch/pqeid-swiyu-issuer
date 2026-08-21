package ch.admin.bj.swiyu.issuer.management;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.infrastructure.web.management.CredentialManagementController;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MLDSASigner;
import com.nimbusds.jose.crypto.MLDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
public class ApplicationIT {

    // PQEID: this constant is reused by CredentialOfferCreateJwtIT to sign both the
    // "enable-jwt-authentication" outer request JWT (verified by JWTResolveRequestWrapper)
    // and the "data_integrity" inner JWT (verified by DataIntegrityService -> JwtUtil,
    // whose VERIFIER_FACTORIES only registers AKP/ML-DSA) - both paths are ML-DSA-44 only,
    // so this key must be ML-DSA-44 too. The matching public key is whitelisted in
    // application-testjwt.yml (application.authentication-jwks / data-integrity-jwks,
    // kid "testkey").
    public static final String privateKey = """
            {
            "kty":"AKP",
            "alg":"ML-DSA-44",
            "kid":"testkey",
            "pub":"y0s5MPLAOhCEYcysEy35rbSAMs_C3wRGgiC-qwKGZSsEbEDBBrtD6No0awlidOH1ImACMGG5gnGjjY0WL8ryl9YPvkmK1oWG-KLIjEz1tc5JlRMlpCCvS-MKPvlxtlWlq8tyNOzmpVvZrTwSJPoFU6URdRS53RhwVBtlmrSOxHlQpL4dUWYjHiDGuT2VBowfrSaLbYsz7hkUeYCzdt6RxaqeEvhI1pwkKtFiq56trHLKpCsXr4H-QzOdMhPZTkPeErBlA83W7QJNnSJjdLOsrsRCTBLAX6iJrltiYKnOwO75erRyid8KW8okVOpQVbfgdSGjdqY3B72qxx1E_d9ik3krQOIvcf21NWxV_LxbS-bG6eiXXftoo-AdorEZPxYcV0cGHzOFxj5Yz3Duv2UPOedEhnTbvtR60dQeW4R1PZKCy89Q1UIGAVyYbdxsysx2i_hipTsecAgj-0ZFmoEgtMKK_KV74YnuiOpzBB2iuzUpp_v1CRbzenOuT4n3KqrK0gtdlzL8DSXNDnAA-_B8IH6ofPvSmJaTvPzhACVKDDOFMGSNq1c0RrW6mNIAD0r8uSgM3zJLmGnHd-gX7w_fU7bZByoNO1_cZNRAvE5YTAIZ2IHHimIRYcUrhxHjgalKgj9KdG-II1oKnR91Vwv8bZP1nI6Mxxzu7rn1AAKneLdC4CkqYdKGlmkxCpfNkLtwLEhiYZjqaZHjdpy2_-jx4CdYY5OK30bvXZvMfMDbN2u1dVDU9fw7J6wAsq8Dhhw18-eDp_UC_OTNXij-2Q-c9Uh5aJpz2KKVH62gFxVyXO6Gp3vMRDD_8GhsF5GJ-IHA90rSZxRt1aKVRzBv9xMNk9G8dsHRvjrNNhPns91z2A_xWkfmLSZke3mtNBurgiFHm-kVuy7DcfA7folhM8JkVyQpRsifFvrqx5xsXqje3zpIMp91JlAxquDOmjgZaPyHT2muKjwGxd-G_2p0mWeHnkLdt2XS6VqtDsxDYxDRc7dbyvWCWxEBSYxpYOyP90m86C8VeTio98eQZlMniZMQVm7m-DNPhDF3mbZs38YCfofe1JWm6ydWUmhoCs0aHZ5lFoz9r0x9GEFudKpGWA2yqNBpI27OhNiv1fNHkVfrRJFm706ERk63TBVpK1NPS-4STtOw2dLWcwNclq8StxdSOXhxb23kdf3-U1P7vheaMDMRhpioDSzNLUkPOkfyIMz8kTvMrcCRHgdhVPtZlsdVXHWjJrowhgyABY9tVRlWC4UOfW7T2TFzquz4YOARPhg1tNExNVwNwc7Ii5HGk5IRZNZwV2lHxZBz7RdoTNW5j3X2c0K7Ftz96J81K2NvHsfWxKzAM4w9WZzbkA4qOkFh_OKdKilvQ1XC7Ou1TCTheuBUg1DsEwA2cYWaKiSSrYNCVgtlcmQrk0nKCRB1-h-Ank_oqjJbuUEaPkY9UJtMuDGcIrvmEI033VlmMDqO4H3nK9azYjt1NbgewggiMAujQ1dvF37acoY9NaZemfhi84SrYMz6KtkoFSd3jFKR5gqbgbOoodpBjNzYjHhGSO54EAZCRZ1aH8TMuZWw4RAZtXDQ7545lLKUs-SIJbkVwk3nJACvZtyjKS8fJQ948bj4xpgjPBr_M3s7DAHGNZIsTB3Btz-DCyISsiXmiepj_fRCORHYQHGLRqX73TIW1XT5bRtr37WdL4koFQqmu-EicG2_G06Ej1CdKuqFdzAWC10rCZ3Dl97hyk2tUvNo8HB4ZA",
            "priv":"y0s5MPLAOhCEYcysEy35rbSAMs_C3wRGgiC-qwKGZSv9MA4aVUNnc9FEgId-WSkf7wok33pSXS2wVR3b82nVPv3oLEcxMAvej3_fJEey6fvZ3V9LtiTg7g9Ezu6qZNM-weyMpTtC2fR0xYzDLo_jnDa1Kip4EACg7TOIqiWHxq4YJWJIAAIbQ0kTBE1IhkwjoUnBoGkjBTIIsQHkAmFAFkQREEnRFk4guWTSQJISiJGKOFGAII5QFGUkAnDiRg3aQIDEAjARxkhLCCwYtm1LoE2cMmoKsS1ZMGDUEGJhiC2EQAkYhGxEsA0klEkQIpEgMjAkkmURA4BQMIVBSEoIJixhokgJA0oDx0nSKDAStBAKBCkMx2VUgowCE1DihCnbGA7ERhJQQkkbxUALBHLBNmUguQghsw3SNgkTAW2CEGQZFIUEhQySqATMIC0SSCiIQFJahAEKIoiLgCmQMHIkiQDiBGQSJ2aZEgoSqUQZJpFjCIwkg4wawwgRRgraEk6csiFgFgKjppCMNknJgpDJkmiUFJIBSGibFkwgiGzQAI1LEgKLxiUSlgQRt3EQySWgiIzQlmWIECGjoAzMpBAkOCTQwgmhkJAcFDJLwDATgoWhsGUgxnAIBhGZmFEbR20SuQnkIjHSxmQIF2pJRonRQAlcJgihFgDYpG1KIo4LEwSIxCjDKFFBhm2kOGJBQmUAt3GhFEpLsgTbEIWBmCkcMkEjNIAbJ3HIgiQQQwQDAXBUOFHYgnECOZHbwGXBkEgCB4wYJo5SAiIJE4QCFmRaAiqJlIDIAmDRKCCjxDHjCCoRFYgEFAUjmQjTEJLRBIKLGIkUAk3DkG0ixI0iE2kCByyEmDCIQkFQkGEbSGXbuIHJxA0YETBEpEyDEIAYs2WARCAjIwHRADFgMoDUuHEMNkGTuI2hKEKZMkCkICyMEgxJJC7hREhKggQDpCTAxmxgJG7LNGTSpolENCpRBm3MBG1alExhFpKUtGjRMmEDlUWKsEAbBIjhRmzkAAiitnHROAwjtixEgDFDlmAQFGCaEpDcMGWghIUKEEwQgkAcQmiCoA0BJQoBElGIwgwTCGYZCJLEkATclHEkMACBhGhihIDSkhERpCxclnDcEGQYGWWcxIzEqGxIOITSEozRpmQRpDDAKAEDGJIDMWYSBzLSOEgBsCXIEEzgMJJgIkHjIEawHPtHdZAr4GoLQ6bon6XlJMSh3GXY69JtIp1kGjIjvSEpYURBpHmO32vOCKCwe4G2BI-_jjYz1PQQZN-lGac_PBftZeiRuTUVDeqPAe1eOyoxkaACSf_71oXqP9k8lw1W-jkjgjqZlzR6PW3kU8y481syB7hOfG7vOaGnryTxiockzKLRM45i4yt5N15Ymad3bYnPgY993ZcZDDmbX7Usuzs3dqWm0OuRjUd7_eSF8p-vFYRgbtp9jpc92v74FMD23RrZuEXyac9IrzrUsvI_b04GkUdS76M1p1aTWKQYEIK8NoGLNQulHZhdN1fOR5Wl9MpUKGyYu1AjKYx-HAJ1SBxOcKKnrU_sIPP6PppHFu1GncViePlLc0xFZ5k329Lu_1ChcATK-gotqnRvkYTuSIfMdMvSUMNEm7DSqZA8IpZyK07_Ljnf6qAXLtXz2xbFt10xtRj7r1oKwttiWRYjOrbNqq7tz-r4s7DvE-h1JCKpSocwuQS0BJ5Sp-SEApHMQePhFJY9CTzOa2GYn9KFZvlC6nHmG8tPZueZJR49Nd1StrSWbBVVREmWyO1AYdKDG5AVSn1V6KhJzwx1LUUWMeQ4mdneK96vAL9Vjjt5WwtYDb1Kj7KZwwt8hKpcWWsfBxjZtWZIQdl8s1zd1cl2-kUGC4cuJsw2euRboeCK1IKFa5WiNude21Idan7mOEVk2UEO-rh8SuV3iLagMwYPBa47NDPJkowcErlpGzFQ14ufwNhspAiCPpNcpZqguJdhPkUOKLf6TPeH2spOzoZBNzwG1KSUQuR9z9JsS4zaxfz5XV-_Xdf0HjJ897vJW6ZVq0eEMX41fqx4vzacpaT_xkODwCebe1RmuH9Kp-rg0fryQLuhurzVwyUaomiLAX9ErDBg3_DD71PXdcOjNMQ0T2RSSzvxZHU1Cc9eqhtbSc_jPOAnFQKm2v9mAloPTBvUVLzI40WkQNRSUd9uNjGimTGHRPN4WOu_6FKDaquVv58QkhfB_P2BaTx8sbaaddy_PJPZvW5c4SWH8KXVSzARQ7ZZmRivOjUmItT2ZlPbLKELtCqx2UMaFI7O145roeab-G28AzvzWEgXAKLRRCQtuQEaT7N3bkbNnWTSyubg_FsBHYIceQ2K8nj7E_OV-5K43FT1XYPXEhiD-aQ7pv1rJf9whEt_sD1ewfdXkc8S70ESXnRDNhcJ-aHc3KS1gOBnUDRWLyT64_KRFWzjiBljwuuGAZUyEl7iO2Z5BuuXhT7OegCx8iaEERV8qzv-_Kbyx-NHDBGxck37HIkbGK_0Pfnpdk_yfKUUy2ydPfoLMQlbyAMdLvN4_in3s35Pw5gvhVAALZ_gEy0BXNhfx0p5GCo0JdtsGY_nJ_H2Njg9C2NrSSxhGFNIEjrAmaZXzWQPnv6ET6d6cuyOt8F266LWURgX-3mth7nUTWEqoYFzU7Dg40W7jZurmrFJodtoUif2TPyqFd_NKPvKErOgJJWVLurryinUVFmOIxZAV3-wpFpyg-WtbUkOAZvddPc-ZDd-EDD5R_HsyF6uJmnpuSH9PUObS5hwI7uq0DQew3FC4_uXJ4sYDRJF0N6CAa6FzygTjBseIhn4EvaSSKOMauoVfuKHxA1TW_dCQMxyQPNNhKyBX9ZLv-UdH4UZDsq_h2yHjBflkmnZIwUCo6Uu3iUjfvqVoUjSOyVikEJweUT7Ian7R2-QVPEqbOD_97-EhVl7TwkUOXzu7E7juicAuP1smRJF17d-lFdnoymOLJXoLShmhCeuWj_vGSXstr9YS813hPcQxigwQxrEsDNeX5yhS2GuleOSJJqp6Hi87hTxBWOODx4Ud3REaMm630KgKx6a9FfJRrNj2ZGlMpOYnRaFwJq1Sdp_uj42BVIAbJQuZ9hu9-egMeQOHCwb-RVbArAKPRO0i1Hn3835LObrN609zYr9L0lrzZ9XVMMLxoahhvddWxvdy9uLxAI9JKbyw1Yfn1CNwtnQ72BDQMvWyw_y5BKmaLtVAInjp0DREoBGaVvHvQG1ta0rMf6ySc3E__EOVid3WB4LjGihus7IqdJWky4W3O2M3SW0ZiALFpErq_vpqResqkww2Ig9RtH490mzLBmI-RxFyBHYuSAZ-QQERQ_luUzf8CkXw_PJeiTddX6AFeK6VKlr03BezeE2rn8hmDl7FFZXZInJ3g8ZXl9Y7hRYt12IixL2Eu60PBRiig"
            }""";
    @Autowired
    private CredentialManagementController credentialController;

    @Test
    void contextLoads() {
        assertThat(credentialController).isNotNull();
    }

    @Test
    void dummyTest() throws JOSEException {

        // Self-contained nimbus-jose-jwt sign/verify round-trip - does not exercise any
        // production wiring (DataIntegrityService/JwtUtil, JWTResolveRequestWrapper) or the
        // shared EC `privateKey` constant above, so it is free to use ML-DSA-44.
        try {
            MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("testkey").generate();
            var otherKey = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_44).keyID("1").generate();
            JWKSet jwks = new JWKSet(java.util.List.of(otherKey.toPublicJWK(), mldsaJWK.toPublicJWK()));
            JWSSigner signer = new MLDSASigner(mldsaJWK);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("alice")
                    .issuer("http://localhost:8080")
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44).keyID(mldsaJWK.getKeyID()).build(),
                    claims);
            jwt.sign(signer);
            String jwtString = jwt.serialize();

            SignedJWT receivedJWT = SignedJWT.parse(jwtString);
            JWK jwk = jwks.getKeyByKeyId(receivedJWT.getHeader().getKeyID());
            JWSVerifier verifier = new MLDSAVerifier(jwk.toMLDSAKey());
            assertTrue(receivedJWT.verify(verifier));

        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testHttpMaxRedirectsSystemPropertyIsSet() {
        var maxRedirects = System.getProperty("http.maxRedirects");
        assertEquals("5", maxRedirects);
    }

}