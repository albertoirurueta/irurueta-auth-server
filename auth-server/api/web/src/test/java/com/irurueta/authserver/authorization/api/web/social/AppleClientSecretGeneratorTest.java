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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AppleClientSecretGenerator}. The key is generated here at run time; none is committed.
 */
class AppleClientSecretGeneratorTest {

    /** Client id of the tests. */
    private static final String CLIENT_ID = "com.example.service";

    /** Team id of the tests. */
    private static final String TEAM_ID = "TEAM123456";

    /** Key id of the tests. */
    private static final String KEY_ID = "KEY1234567";

    /** Lifetime of a secret, in minutes. */
    private static final long TTL_MINUTES = 10L;

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /**
     * Verifies the content and the signature of a generated secret: the claims Apple requires and an ES256 signature
     * that the public key verifies.
     *
     * @throws GeneralSecurityException if the key cannot be generated or the signature cannot be verified.
     * @throws ParseException           if the secret is not a JWT.
     * @throws JOSEException            if the signature cannot be verified.
     */
    @Test
    void generate_whenCalled_returnsAnEs256JwtWithTheClaimsAppleRequires()
            throws GeneralSecurityException, ParseException, JOSEException {
        final var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        final var pair = generator.generateKeyPair();
        final var secrets = new AppleClientSecretGenerator(settings(), (ECPrivateKey) pair.getPrivate(),
                Clock.fixed(NOW, ZoneOffset.UTC));

        final var jwt = SignedJWT.parse(secrets.generate());

        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertEquals(KEY_ID, jwt.getHeader().getKeyID());
        assertEquals(TEAM_ID, jwt.getJWTClaimsSet().getIssuer());
        assertEquals(CLIENT_ID, jwt.getJWTClaimsSet().getSubject());
        assertEquals(List.of("https://appleid.apple.com"), jwt.getJWTClaimsSet().getAudience());
        assertEquals(NOW.getEpochSecond(), jwt.getJWTClaimsSet().getIssueTime().toInstant().getEpochSecond());
        assertEquals(NOW.plus(Duration.ofMinutes(TTL_MINUTES)).getEpochSecond(),
                jwt.getJWTClaimsSet().getExpirationTime().toInstant().getEpochSecond());
        assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) pair.getPublic())));
        assertEquals(CLIENT_ID, secrets.clientId());
    }

    /**
     * Verifies that the secret is cached while it is young and renewed after half of its lifetime.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void generate_whenCalledAgain_reusesTheSecretUntilHalfItsLifetimeHasPassed() throws GeneralSecurityException {
        final var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        final var key = (ECPrivateKey) generator.generateKeyPair().getPrivate();
        final var clock = new MutableClock(NOW);
        final var secrets = new AppleClientSecretGenerator(settings(), key, clock);

        final var first = secrets.generate();
        clock.advance(Duration.ofMinutes(TTL_MINUTES / 2 - 1));
        final var second = secrets.generate();
        clock.advance(Duration.ofMinutes(2));
        final var third = secrets.generate();

        assertSame(first, second);
        assertNotEquals(first, third);
    }

    /**
     * Verifies that a key on a curve the signer does not support is refused when the generator is built.
     */
    @Test
    void constructor_whenKeyCannotSignWithEs256_throwsIllegalArgumentException() {
        final var key = mock(ECPrivateKey.class);
        final var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        final var settings = settings();

        assertThrows(IllegalArgumentException.class, () -> new AppleClientSecretGenerator(settings, key, clock));
    }

    /**
     * Builds the settings of Apple.
     *
     * @return the settings.
     */
    private static SocialProperties.Provider settings() {
        return new SocialProperties.Provider(CLIENT_ID, null, false, null, null, TEAM_ID, KEY_ID, "pem",
                Duration.ofMinutes(TTL_MINUTES));
    }

    /**
     * A clock a test moves forward. It is a Java clock, not a double of this repository's ports.
     */
    private static final class MutableClock extends Clock {

        /** The current instant. */
        private Instant now;

        /**
         * Creates the clock.
         *
         * @param now initial instant.
         */
        MutableClock(final Instant now) {
            this.now = now;
        }

        /**
         * Moves the clock forward.
         *
         * @param duration how far.
         */
        void advance(final Duration duration) {
            now = now.plus(duration);
        }

        /**
         * Gets the zone.
         *
         * @return UTC.
         */
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        /**
         * Gets a clock in another zone.
         *
         * @param zone the zone.
         * @return this clock.
         */
        @Override
        public Clock withZone(final ZoneId zone) {
            return this;
        }

        /**
         * Gets the current instant.
         *
         * @return the instant.
         */
        @Override
        public Instant instant() {
            return now;
        }
    }
}
