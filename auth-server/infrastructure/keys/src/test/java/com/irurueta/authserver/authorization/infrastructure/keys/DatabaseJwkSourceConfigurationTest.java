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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.keys.ActiveSigningKeyUseCase;
import com.irurueta.authserver.authorization.application.keys.PublishedSigningKeysUseCase;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

/**
 * Unit tests of {@link DatabaseJwkSourceConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class DatabaseJwkSourceConfigurationTest {

    /** Instant of the fixed clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Time to live of the caches. */
    private static final Duration TTL = Duration.ofMinutes(1);

    /** Use case that finds the published keys. */
    @Mock
    private PublishedSigningKeysUseCase published;

    /** Use case that finds the active key. */
    @Mock
    private ActiveSigningKeyUseCase active;

    /** Clock of the caches. */
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    /** Cipher shared by the generator and the mapper. */
    private final AesGcmKeyCipher cipher = new AesGcmKeyCipher(KeyTestSupport.randomProperties());

    /** Mapper the configuration converts the stored keys with. */
    private final SigningKeyJwkMapper mapper = new SigningKeyJwkMapper(cipher);

    /** Configuration under test. */
    private final DatabaseJwkSourceConfiguration configuration = new DatabaseJwkSourceConfiguration();

    /** The next key. */
    private SigningKey next;

    /** The active key. */
    private SigningKey current;

    /** A retired key. */
    private SigningKey retired;

    /**
     * Generates three keys, one per state.
     */
    @BeforeEach
    void setUp() {
        final var generator = new RsaSigningKeyGenerator(cipher);
        next = generator.generate(NOW);
        current = generator.generate(NOW).activate(NOW);
        retired = generator.generate(NOW).activate(NOW).retire(NOW);
    }

    /**
     * Verifies that the JWKS lists every published key, each with its public half only.
     *
     * @throws Exception if a key cannot be selected.
     */
    @Test
    void jwkSource_whenSeveralKeysArePublished_listsAllOfThemWithoutPrivateParts() throws Exception {
        when(published.execute()).thenReturn(List.of(next, current, retired));
        final var source = configuration.jwkSource(configuration.publishedJwkSet(published, mapper, clock, TTL));

        final var keys = source.get(everything(), null);

        assertEquals(Set.of(next.kid(), current.kid(), retired.kid()),
                keys.stream().map(JWK::getKeyID).collect(Collectors.toSet()));
        assertTrue(keys.stream().noneMatch(JWK::isPrivate));
    }

    /**
     * Verifies that, although several keys are published, exactly one of them signs: the active one.
     *
     * @throws Exception if a key cannot be selected.
     */
    @Test
    void jwtEncoder_whenSeveralKeysArePublished_signsOnlyWithTheActiveKey() throws Exception {
        when(published.execute()).thenReturn(List.of(next, current, retired));
        when(active.execute()).thenReturn(Optional.of(current));
        final var encoder = configuration.jwtEncoder(configuration.signingJwkSet(active, mapper, clock, TTL));
        final var claims = JwtClaimsSet.builder().subject(UUID.randomUUID().toString()).build();
        final var header = JwsHeader.with(SignatureAlgorithm.RS256).build();

        final var token = encoder.encode(JwtEncoderParameters.from(header, claims));

        assertEquals(current.kid(), token.getHeaders().get("kid"));
        final var signing = configuration.signingJwkSet(active, mapper, clock, TTL).get();
        assertEquals(1, signing.getKeys().size());
        assertTrue(signing.getKeys().getFirst().isPrivate());
        final var listed = configuration.publishedJwkSet(published, mapper, clock, TTL).get().getKeys();
        assertEquals(published.execute().size(), listed.size());
    }

    /**
     * Verifies that nothing can be signed before the first rotation has created an active key.
     */
    @Test
    void jwtEncoder_whenThereIsNoActiveKey_throwsJwtEncodingException() {
        when(active.execute()).thenReturn(Optional.empty());
        final var encoder = configuration.jwtEncoder(configuration.signingJwkSet(active, mapper, clock, TTL));
        final var claims = JwtClaimsSet.builder().subject(UUID.randomUUID().toString()).build();
        final var header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        final var parameters = JwtEncoderParameters.from(header, claims);

        assertThrows(JwtEncodingException.class, () -> encoder.encode(parameters));
    }

    /**
     * Verifies that the public set does not hide any key from a selector.
     *
     * @throws Exception if a key cannot be selected.
     */
    @Test
    void jwkSource_whenNoKeysArePublished_isEmpty() throws Exception {
        when(published.execute()).thenReturn(List.of());
        final var source = configuration.jwkSource(configuration.publishedJwkSet(published, mapper, clock, TTL));

        assertFalse(source.get(everything(), null).iterator().hasNext());
    }

    /**
     * Creates a selector that matches every key.
     *
     * @return the selector.
     */
    private static JWKSelector everything() {
        return new JWKSelector(new JWKMatcher.Builder().build());
    }
}
