package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.jwtutil.JwtUtil;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.NotImplementedError;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.stream.Collectors;
import java.util.Set;


/**
 * Wrapper for a request with a JWT encoded content.
 * Reading from the wrapper only returns the claims of the JWT as the Request
 * body.
 * Create by using the static method <code>createAndValidate</code>
 */
@Getter
@Slf4j
public class JWTResolveRequestWrapper extends HttpServletRequestWrapper {
    private final SignedJWT jwt;
    private final String dataClaim;

    private JWTResolveRequestWrapper(HttpServletRequest request, JWKSet allowedKeys, Set<JWSAlgorithm> accepted)
            throws IOException, ParseException {
        super(request);
        String jwtString = request.getReader().lines().collect(Collectors.joining());
        this.jwt = SignedJWT.parse(jwtString);
        // PQEID: kid lookup + verifier from the key type, gated by the issuer policy (shared JwtUtil logic,
        // replaces this class's private ML-DSA-only copy)
        JwtUtil.verifySignedJwt(this.jwt, allowedKeys, accepted);
        this.dataClaim = jwt.getJWTClaimsSet().getStringClaim("data");
    }

    public static JWTResolveRequestWrapper createAndValidate(HttpServletRequest request, JWKSet allowedKeys,
                                                             Set<JWSAlgorithm> accepted) {
        try {
            return new JWTResolveRequestWrapper(request, allowedKeys, accepted);
        } catch (Exception e) {
            log.info("Parsing communication JWT failed.", e);
            throw new BadRequestException("Request is not JWT encoded");
        }
    }

    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream buffer = new ByteArrayInputStream(dataClaim.getBytes());
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return buffer.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                throw new NotImplementedError("setReadListener Not implemented");
            }

            @Override
            public int read() {
                return buffer.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }
}