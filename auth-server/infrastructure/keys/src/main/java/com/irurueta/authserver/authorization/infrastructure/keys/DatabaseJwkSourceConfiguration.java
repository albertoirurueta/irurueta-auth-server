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
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Clock;
import java.time.Duration;
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
 * active key with its private half, so signing never has to choose between several keys. The conversion of the
 * stored keys into JSON Web Keys belongs to the {@link SigningKeyJwkMapper}.
 */
@Configuration(proxyBeanMethods = false)
public class DatabaseJwkSourceConfiguration {

    /**
     * Creates the cached set of public keys.
     *
     * @param published use case that finds the keys to publish.
     * @param mapper    maps the keys onto JSON Web Keys.
     * @param clock     source of the current time.
     * @param ttl       how long the set is kept ({@code authserver.keys.jwks-cache-ttl} in {@code application.yml}).
     * @return the cache; call {@link CachedJwkSet#refresh()} after a rotation.
     */
    @Bean
    public CachedJwkSet publishedJwkSet(
            final PublishedSigningKeysUseCase published, final SigningKeyJwkMapper mapper, final Clock clock,
            @Value("${authserver.keys.jwks-cache-ttl}") final Duration ttl) {
        return new CachedJwkSet(() -> mapper.toPublicJwkSet(published.execute()), ttl, clock);
    }

    /**
     * Creates the cached set holding only the active key, with its private half.
     *
     * @param active use case that finds the active key.
     * @param mapper maps the key onto a JSON Web Key, decrypting its private half.
     * @param clock  source of the current time.
     * @param ttl    how long the set is kept ({@code authserver.keys.jwks-cache-ttl} in {@code application.yml}).
     * @return the cache; call {@link CachedJwkSet#refresh()} after a rotation.
     */
    @Bean
    public CachedJwkSet signingJwkSet(
            final ActiveSigningKeyUseCase active, final SigningKeyJwkMapper mapper, final Clock clock,
            @Value("${authserver.keys.jwks-cache-ttl}") final Duration ttl) {
        return new CachedJwkSet(() -> mapper.toSigningJwkSet(active.execute()), ttl, clock);
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
}
// end::keys-jwk-source[]
