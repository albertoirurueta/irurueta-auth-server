/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

// tag::jwt-service[]
/**
 * Issues and verifies purpose-bound tokens as JWTs signed with the active signing key and verified against the
 * published keys. Verification checks the signature, the issuer, the timestamps and then the purpose; every failure
 * is reported the same way, as an empty result.
 */
@Component
public class NimbusSignedTokenService implements SignedTokenService {

    /** Name of the claim that holds the purpose of the token. */
    static final String PURPOSE_CLAIM = "purpose";

    /** Source of the current time. */
    private final Clock clock;

    /** Issuer written to, and required of, every token. */
    private final String issuer;

    /** Signs tokens. */
    private final JwtEncoder encoder;

    /** Verifies tokens. */
    private final JwtDecoder decoder;

    /**
     * Creates the service.
     *
     * @param encoder   signs tokens with the active key.
     * @param jwkSource public keys the signatures are verified against.
     * @param clock     source of the current time.
     * @param issuer    issuer of the tokens ({@code spring.security.oauth2.authorizationserver.issuer}).
     */
    public NimbusSignedTokenService(
            final JwtEncoder encoder, final JWKSource<SecurityContext> jwkSource, final Clock clock,
            @Value("${spring.security.oauth2.authorizationserver.issuer}") final String issuer) {
        this.encoder = encoder;
        this.clock = clock;
        this.issuer = issuer;
        final var timestamps = new JwtTimestampValidator();
        timestamps.setClock(clock);
        final var nimbusDecoder = NimbusJwtDecoder.withJwkSource(jwkSource)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        nimbusDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(
                List.<OAuth2TokenValidator<Jwt>>of(new JwtIssuerValidator(issuer), timestamps)));
        decoder = nimbusDecoder;
    }

    /**
     * Issues a signed token.
     *
     * @param subject who or what the token is about.
     * @param purpose what the token allows.
     * @param ttl     how long the token stays valid.
     * @return the compact token.
     */
    @Override
    public String issue(final String subject, final String purpose, final Duration ttl) {
        final var now = clock.instant();
        final var claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim(PURPOSE_CLAIM, purpose)
                .build();
        final var header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    /**
     * Verifies a token.
     *
     * @param token   the compact token.
     * @param purpose purpose the token must have been issued for.
     * @return the subject, or an empty optional when the token is expired, tampered, malformed, from another issuer or
     *         issued for another purpose.
     */
    @Override
    public Optional<String> verify(final String token, final String purpose) {
        try {
            final var jwt = decoder.decode(token);
            if (purpose != null && purpose.equals(jwt.getClaimAsString(PURPOSE_CLAIM))) {
                return Optional.ofNullable(jwt.getSubject());
            }
            return Optional.empty();
        } catch (final JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
// end::jwt-service[]
