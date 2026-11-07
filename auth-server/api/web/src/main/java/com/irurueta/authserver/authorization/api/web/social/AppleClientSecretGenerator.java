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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.TimeUnit;

// tag::social-apple-secret[]
/**
 * Generates the client secret Sign in with Apple requires: a JWT signed with ES256 by the key Apple issued
 * ({@code iss} the team id, {@code sub} the client id, {@code aud} {@code https://appleid.apple.com}, header
 * {@code kid} the key id), valid for a short time. The token request of the framework asks for it each time, so the
 * secret is cached and renewed when half of its lifetime has passed.
 *
 * <p>It does not use the {@code JwtEncoder} of the server's own signing keys: Apple verifies the secret with the key
 * registered in its developer account, so only that key can sign it. It is a dedicated Nimbus signer over the Apple
 * key supplied from the environment.
 */
public final class AppleClientSecretGenerator {

    /** Audience Apple requires in the client secret. */
    static final String AUDIENCE = "https://appleid.apple.com";

    /** The secret is renewed when this fraction of its lifetime has passed. */
    private static final int RENEWAL_DIVISOR = 2;

    /** Client id registered with Apple (the services id). */
    private final String clientId;

    /** Apple developer team id. */
    private final String teamId;

    /** Id of the key that signs the secret. */
    private final String keyId;

    /** Lifetime of a secret. */
    private final Duration ttl;

    /** Source of the current time. */
    private final Clock clock;

    /** Signs with the Apple key. */
    private final ECDSASigner signer;

    /** Holds the current secret until it is half way through its life. */
    private final Cache<String, String> cache;

    /**
     * Creates the generator.
     *
     * @param settings settings of the Apple provider.
     * @param key      private key Apple issued.
     * @param clock    source of the current time.
     * @throws IllegalArgumentException if the key cannot sign with ES256.
     */
    public AppleClientSecretGenerator(
            final SocialProperties.Provider settings, final ECPrivateKey key, final Clock clock) {
        this.clientId = settings.clientId();
        this.teamId = settings.teamId();
        this.keyId = settings.keyId();
        this.ttl = settings.clientSecretTtl();
        this.clock = clock;
        try {
            this.signer = new ECDSASigner(key);
        } catch (final JOSEException e) {
            throw new IllegalArgumentException("The Apple key cannot sign with ES256", e);
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(1)
                .expireAfterWrite(ttl.dividedBy(RENEWAL_DIVISOR))
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .build();
    }

    /**
     * Returns a client secret that is valid now.
     *
     * @return the signed JWT.
     */
    public String generate() {
        return cache.get(clientId, ignored -> sign());
    }

    /**
     * Signs a new secret.
     *
     * @return the serialized JWT.
     */
    private String sign() {
        final var now = clock.instant();
        final var claims = new JWTClaimsSet.Builder()
                .issuer(teamId)
                .subject(clientId)
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .build();
        final var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).type(JOSEObjectType.JWT).build(), claims);
        try {
            jwt.sign(signer);
        } catch (final JOSEException e) {
            throw new IllegalStateException("The Apple client secret cannot be signed", e);
        }
        return jwt.serialize();
    }
}
// end::social-apple-secret[]
