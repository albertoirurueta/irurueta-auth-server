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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

import com.irurueta.authserver.authorization.application.keys.ActiveSigningKeyUseCase;
import com.irurueta.authserver.authorization.application.keys.PublishedSigningKeysUseCase;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.JwtEncoder;

/**
 * Unit tests of {@link NimbusSignedTokenService}.
 */
@ExtendWith(MockitoExtension.class)
class NimbusSignedTokenServiceTest {

    /** Instant at which tokens are issued. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Lifetime of the tokens. */
    private static final Duration TTL = Duration.ofMinutes(10);

    /** Issuer of the tokens. */
    private static final String ISSUER = "http://localhost:9000";

    /** Purpose of the tokens. */
    private static final String PURPOSE = "verify-email";

    /** Use case that finds the published keys. */
    @Mock
    private PublishedSigningKeysUseCase published;

    /** Use case that finds the active key. */
    @Mock
    private ActiveSigningKeyUseCase active;

    /** Subject of the tokens. */
    private final String subject = UUID.randomUUID().toString();

    /** Encoder that signs with the active key. */
    private JwtEncoder encoder;

    /** Source of the public keys. */
    private JWKSource<SecurityContext> jwkSource;

    /** Service under test, issuing at {@link #NOW}. */
    private NimbusSignedTokenService service;

    /**
     * Creates the service over one generated key. The stubs are lenient because not every test reaches the keys.
     */
    @BeforeEach
    void setUp() {
        final var cipher = new AesGcmKeyCipher(KeyTestSupport.randomProperties());
        final SigningKey key = new RsaSigningKeyGenerator(cipher).generate(NOW).activate(NOW);
        lenient().when(published.execute()).thenReturn(List.of(key));
        lenient().when(active.execute()).thenReturn(Optional.of(key));
        final var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        final var configuration = new DatabaseJwkSourceConfiguration();
        encoder = configuration.jwtEncoder(configuration.signingJwkSet(active, cipher, clock, Duration.ofMinutes(1)));
        jwkSource = configuration.jwkSource(configuration.publishedJwkSet(published, clock, Duration.ofMinutes(1)));
        service = serviceAt(NOW, ISSUER);
    }

    /**
     * Verifies that a token verifies for its purpose and gives back its subject.
     */
    @Test
    void verify_whenTokenIsValid_returnsSubject() {
        final var token = service.issue(subject, PURPOSE, TTL);

        assertEquals(Optional.of(subject), service.verify(token, PURPOSE));
    }

    /**
     * Verifies that an expired token is rejected.
     */
    @Test
    void verify_whenTokenIsExpired_returnsEmpty() {
        final var token = service.issue(subject, PURPOSE, TTL);

        assertTrue(serviceAt(NOW.plus(TTL).plus(Duration.ofHours(1)), ISSUER).verify(token, PURPOSE).isEmpty());
    }

    /**
     * Verifies that a token is rejected for a purpose other than its own.
     */
    @Test
    void verify_whenPurposeDiffers_returnsEmpty() {
        final var token = service.issue(subject, PURPOSE, TTL);

        assertTrue(service.verify(token, "reset-password").isEmpty());
        assertTrue(service.verify(token, null).isEmpty());
    }

    /**
     * Verifies that a token whose signature was altered is rejected.
     */
    @Test
    void verify_whenSignatureIsTampered_returnsEmpty() {
        final var token = service.issue(subject, PURPOSE, TTL);
        final var signatureStart = token.lastIndexOf('.') + 1;
        final var middle = signatureStart + (token.length() - signatureStart) / 2;
        final var replacement = token.charAt(middle) == 'A' ? 'B' : 'A';
        final var tampered = token.substring(0, middle) + replacement + token.substring(middle + 1);

        assertNotEquals(token, tampered);
        assertTrue(service.verify(tampered, PURPOSE).isEmpty());
    }

    /**
     * Verifies that a token whose payload was swapped for another one is rejected.
     */
    @Test
    void verify_whenPayloadIsReplaced_returnsEmpty() {
        final var token = service.issue(subject, PURPOSE, TTL);
        final var other = service.issue(UUID.randomUUID().toString(), PURPOSE, TTL);
        final var parts = token.split("\\.");
        final var otherParts = other.split("\\.");

        assertTrue(service.verify(parts[0] + "." + otherParts[1] + "." + parts[2], PURPOSE).isEmpty());
    }

    /**
     * Verifies that a token from another issuer is rejected.
     */
    @Test
    void verify_whenIssuerDiffers_returnsEmpty() {
        final var token = serviceAt(NOW, "http://other.example").issue(subject, PURPOSE, TTL);

        assertTrue(service.verify(token, PURPOSE).isEmpty());
    }

    /**
     * Verifies that something that is not a token is rejected.
     */
    @Test
    void verify_whenTokenIsMalformed_returnsEmpty() {
        assertTrue(service.verify("not a token", PURPOSE).isEmpty());
    }

    /**
     * Creates a service that reads the time from a fixed clock.
     *
     * @param instant instant of the clock.
     * @param issuer  issuer of the service.
     * @return the service.
     */
    private NimbusSignedTokenService serviceAt(final Instant instant, final String issuer) {
        return new NimbusSignedTokenService(encoder, jwkSource, Clock.fixed(instant, ZoneOffset.UTC), issuer);
    }
}
