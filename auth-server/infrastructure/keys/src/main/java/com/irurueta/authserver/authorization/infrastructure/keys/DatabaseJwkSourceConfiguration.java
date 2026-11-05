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

import com.irurueta.authserver.authorization.application.keys.ActiveSigningKeyUseCase;
import com.irurueta.authserver.authorization.application.keys.PublishedSigningKeysUseCase;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

// tag::keys-jwk-source[]
/**
 * Serves the signing keys kept by the key use cases. Two views of them exist on purpose: the public JWKS lists the
 * active key, the next key and the still-valid retired keys, whereas the {@link JwtEncoder} only ever sees the single
 * active key with its private half, so signing never has to choose between several keys.
 */
@Configuration(proxyBeanMethods = false)
public class DatabaseJwkSourceConfiguration {

    /**
     * Creates the cached set of public keys.
     *
     * @param published use case that finds the keys to publish.
     * @param clock     source of the current time.
     * @param ttl       how long the set is kept ({@code authserver.keys.jwks-cache-ttl}, default 30 seconds).
     * @return the cache; call {@link CachedJwkSet#refresh()} after a rotation.
     */
    @Bean
    public CachedJwkSet publishedJwkSet(
            final PublishedSigningKeysUseCase published, final Clock clock,
            @Value("${authserver.keys.jwks-cache-ttl:PT30S}") final Duration ttl) {
        return new CachedJwkSet(() -> publicSet(published.execute()), ttl, clock);
    }

    /**
     * Creates the cached set holding only the active key, with its private half.
     *
     * @param active use case that finds the active key.
     * @param cipher decrypts the private half.
     * @param clock  source of the current time.
     * @param ttl    how long the set is kept ({@code authserver.keys.jwks-cache-ttl}, default 30 seconds).
     * @return the cache; call {@link CachedJwkSet#refresh()} after a rotation.
     */
    @Bean
    public CachedJwkSet signingJwkSet(
            final ActiveSigningKeyUseCase active, final AesGcmKeyCipher cipher, final Clock clock,
            @Value("${authserver.keys.jwks-cache-ttl:PT30S}") final Duration ttl) {
        return new CachedJwkSet(() -> signingSet(active, cipher), ttl, clock);
    }

    /**
     * Creates the source of the public JWKS. It never holds a private key.
     *
     * @param publishedJwkSet the cached public keys.
     * @return the source.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(@Qualifier("publishedJwkSet") final CachedJwkSet publishedJwkSet) {
        return (selector, context) -> selector.select(publishedJwkSet.get());
    }

    /**
     * Creates the encoder that signs tokens with the active key.
     *
     * @param signingJwkSet the cached active key.
     * @return the encoder.
     */
    @Bean
    public JwtEncoder jwtEncoder(@Qualifier("signingJwkSet") final CachedJwkSet signingJwkSet) {
        return new NimbusJwtEncoder((selector, context) -> selector.select(signingJwkSet.get()));
    }

    /**
     * Builds the set of public keys.
     *
     * @param keys the keys to publish.
     * @return the set, with the public half of each key only.
     */
    private static JWKSet publicSet(final List<SigningKey> keys) {
        return new JWKSet(keys.stream().map(key -> parse(key.publicJwk()).toPublicJWK()).toList());
    }

    /**
     * Builds the set holding the active key.
     *
     * @param active use case that finds the active key.
     * @param cipher decrypts the private half.
     * @return the set; empty before the first rotation has created an active key.
     */
    private static JWKSet signingSet(final ActiveSigningKeyUseCase active, final AesGcmKeyCipher cipher) {
        return new JWKSet(active.execute().map(key -> parse(cipher.decrypt(key.encryptedPrivateJwk())))
                .stream().toList());
    }

    /**
     * Parses a JSON Web Key.
     *
     * @param json the key as JSON.
     * @return the key.
     * @throws IllegalStateException if the text is not a valid key.
     */
    private static JWK parse(final String json) {
        try {
            return JWK.parse(json);
        } catch (final ParseException e) {
            throw new IllegalStateException("A stored signing key is not a valid JWK", e);
        }
    }
}
// end::keys-jwk-source[]
