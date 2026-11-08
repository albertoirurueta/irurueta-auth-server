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
package com.irurueta.authserver.authorization.api.web.clientauth;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.util.HexFormat;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionDecoderFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

// tag::clientauth-assertion-decoder[]
/**
 * Creates the decoder of the client assertions of a client. A client with a registered JWK set
 * ({@code settings.client.jwks}) is verified against those keys; any other client goes through the framework's
 * factory, which reads the keys of its {@code jwkSetUrl} (or the shared secret of {@code client_secret_jwt}). Both
 * add the framework's default assertion validators (issuer, subject, audience including the PAR endpoint, expiry)
 * and the {@link ReplayRejectingJwtValidator}. The framework's own factory caches a decoder per client forever, so
 * this one caches the decoders itself, per client identifier and a hash of the settings that decide the keys, and a
 * client whose keys or algorithm were changed is verified against the new ones.
 */
@RequiredArgsConstructor
public class RegisteredJwksClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

    /** Name of the custom client setting that holds the registered public JWK set as JSON. */
    public static final String JWKS_SETTING = "settings.client.jwks";

    /** Most decoders kept. */
    private static final long MAX_DECODERS = 1_000L;

    /** Time an unused decoder is kept. */
    private static final Duration IDLE = Duration.ofMinutes(10);

    /** Separator of the fields hashed into a cache key. */
    private static final char SEPARATOR = '\u0000';

    /** Algorithm of the settings hash. */
    private static final String HASH_ALGORITHM = "SHA-256";

    /** Records the use of an assertion and checks its lifetime. */
    private final ReplayRejectingJwtValidator replayValidator;

    /** Decoders by client and settings hash. */
    private final Cache<String, JwtDecoder> decoders = Caffeine.newBuilder().maximumSize(MAX_DECODERS)
            .expireAfterAccess(IDLE).build();

    /**
     * Returns the decoder of the assertions of a client.
     *
     * @param registeredClient the client that authenticates.
     * @return the decoder, which also rejects a replayed assertion.
     * @throws OAuth2AuthenticationException {@code invalid_client} if the client has registered keys but no signing
     *                                       algorithm, or the keys cannot be read; the framework's factory throws it
     *                                       too when it has no way to find the keys.
     */
    @Override
    public JwtDecoder createDecoder(final RegisteredClient registeredClient) {
        return decoders.get(cacheKey(registeredClient), key -> build(registeredClient));
    }

    /**
     * Builds a decoder.
     *
     * @param registeredClient the client that authenticates.
     * @return the decoder.
     */
    private JwtDecoder build(final RegisteredClient registeredClient) {
        final var validators = validatorsOf(registeredClient);
        final var jwks = registeredClient.getClientSettings().<Object>getSetting(JWKS_SETTING);
        if (!(jwks instanceof String json) || !StringUtils.hasText(json)) {
            final var framework = new JwtClientAssertionDecoderFactory();
            framework.setJwtValidatorFactory(client -> validators);
            return framework.createDecoder(registeredClient);
        }
        final var algorithm = registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm();
        if (algorithm == null) {
            throw invalidClient("The token endpoint signing algorithm of the client is not registered");
        }
        final var signatureAlgorithm = SignatureAlgorithm.from(algorithm.getName());
        if (signatureAlgorithm == null) {
            throw invalidClient("The token endpoint signing algorithm of the client is not an asymmetric one");
        }
        final JWKSet keys;
        try {
            keys = JWKSet.parse(json);
        } catch (ParseException e) {
            throw invalidClient("The registered keys of the client cannot be read");
        }
        final var decoder = NimbusJwtDecoder.withJwkSource(new ImmutableJWKSet<SecurityContext>(keys))
                .jwsAlgorithm(signatureAlgorithm).build();
        decoder.setJwtValidator(validators);
        return decoder;
    }

    /**
     * Combines the default assertion validators with the replay one, failing fast so the replay validator only runs
     * (and only records the {@code jti}) for an assertion that passed every default check.
     *
     * @param registeredClient the client that authenticates.
     * @return the validator.
     */
    private OAuth2TokenValidator<Jwt> validatorsOf(final RegisteredClient registeredClient) {
        final var defaults = JwtClientAssertionDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY.apply(registeredClient);
        final var validators = new DelegatingOAuth2TokenValidator<>(defaults, replayValidator);
        validators.setFailOnError(true);
        return validators;
    }

    /**
     * Builds the cache key: the client identifier and the hash of everything that decides which keys verify it.
     *
     * @param registeredClient the client that authenticates.
     * @return the key.
     */
    private static String cacheKey(final RegisteredClient registeredClient) {
        final var settings = registeredClient.getClientSettings();
        final var algorithm = settings.getTokenEndpointAuthenticationSigningAlgorithm();
        final var material = String.join(String.valueOf(SEPARATOR),
                String.valueOf(settings.<Object>getSetting(JWKS_SETTING)),
                String.valueOf(settings.getJwkSetUrl()),
                algorithm == null ? "" : algorithm.getName(),
                String.valueOf(registeredClient.getClientSecret()));
        try {
            final var hash = MessageDigest.getInstance(HASH_ALGORITHM)
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return registeredClient.getClientId() + SEPARATOR + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " is always available", e);
        }
    }

    /**
     * Builds the {@code invalid_client} error.
     *
     * @param description what is wrong.
     * @return the exception.
     */
    private static OAuth2AuthenticationException invalidClient(final String description) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, description, null));
    }
}
// end::clientauth-assertion-decoder[]
