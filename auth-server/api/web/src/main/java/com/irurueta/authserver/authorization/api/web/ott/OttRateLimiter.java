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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.ratelimit.FixedWindowBuckets;
import java.time.Clock;
import java.util.Locale;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

// tag::ott-rate-limit[]
/**
 * Rate limiter of the one-time token endpoints, on the pattern of the account endpoints' limiter: Bucket4j token
 * buckets in Caffeine caches ({@link FixedWindowBuckets}). Requests for a token (generation) and submissions of a token
 * or code (verification) are limited separately, and each twice: per client address and per identifier (the user name
 * the request names), so a single client cannot flood the mailboxes and the SMS budget, many clients cannot aim at one
 * account, and a code cannot be guessed faster than the limits allow, on top of the attempt counter of the code
 * itself. The identifier is limited whether or not it belongs to an account, so the limit never tells which ones
 * exist.
 *
 * <p>Each bucket holds the limit of its key and is refilled all at once every
 * {@link OttRateLimitProperties#window()}. The buckets live in this instance only: several instances each apply the
 * limits on their own. The client address is {@code request.getRemoteAddr()}, so behind a proxy
 * {@code server.forward-headers-strategy} must be set for it to be the real client.
 */
@Component
@EnableConfigurationProperties(OttRateLimitProperties.class)
public final class OttRateLimiter {

    /** Key used when the client address is unknown. */
    private static final String UNKNOWN_CLIENT = "unknown";

    /** Limits, window and bound of the tracked keys. */
    private final OttRateLimitProperties properties;

    /** Buckets of the token requests per client address. */
    private final FixedWindowBuckets generationClients;

    /** Buckets of the token requests per identifier. */
    private final FixedWindowBuckets generationIdentifiers;

    /** Buckets of the submissions per client address. */
    private final FixedWindowBuckets verificationClients;

    /** Buckets of the submissions per identifier. */
    private final FixedWindowBuckets verificationIdentifiers;

    /**
     * Creates the limiter.
     *
     * @param properties limits, window and bound of the tracked keys.
     * @param clock      source of the current time.
     */
    public OttRateLimiter(final OttRateLimitProperties properties, final Clock clock) {
        this.properties = properties;
        generationClients = buckets(clock);
        generationIdentifiers = buckets(clock);
        verificationClients = buckets(clock);
        verificationIdentifiers = buckets(clock);
    }

    /**
     * Counts one request for a token and rejects it once a limit is exceeded.
     *
     * @param clientAddress address of the calling client.
     * @param identifier    identifier the request names, or {@code null} when it names none.
     * @throws OttRateLimitExceededException if the client or the identifier exceeded its limit.
     */
    public void checkGeneration(final String clientAddress, final String identifier) {
        check(generationClients, properties.generationPerClient(), generationIdentifiers,
                properties.generationPerIdentifier(), clientAddress, identifier);
    }

    /**
     * Counts one submission of a token or a code and rejects it once a limit is exceeded.
     *
     * @param clientAddress address of the calling client.
     * @param identifier    identifier the submission is for, or {@code null} when it names none (a magic link).
     * @throws OttRateLimitExceededException if the client or the identifier exceeded its limit.
     */
    public void checkVerification(final String clientAddress, final String identifier) {
        check(verificationClients, properties.verificationPerClient(), verificationIdentifiers,
                properties.verificationPerIdentifier(), clientAddress, identifier);
    }

    /**
     * Tells how many keys are tracked, after any pending eviction.
     *
     * @return the number of keys of the four kinds.
     */
    long trackedKeys() {
        return generationClients.trackedKeys() + generationIdentifiers.trackedKeys()
                + verificationClients.trackedKeys() + verificationIdentifiers.trackedKeys();
    }

    /**
     * Applies the client and the identifier limits of one kind of request.
     *
     * @param clients         buckets per client address.
     * @param clientLimit     requests per client address per window.
     * @param identifiers     buckets per identifier.
     * @param identifierLimit requests per identifier per window.
     * @param clientAddress   address of the calling client.
     * @param identifier      identifier, or {@code null}.
     * @throws OttRateLimitExceededException if a limit is exceeded.
     */
    private void check(final FixedWindowBuckets clients, final int clientLimit, final FixedWindowBuckets identifiers,
                       final int identifierLimit, final String clientAddress, final String identifier) {
        if (!properties.enabled()) {
            return;
        }
        consume(clients, clientAddress == null ? UNKNOWN_CLIENT : clientAddress, clientLimit);
        if (identifier != null) {
            consume(identifiers, identifier.toLowerCase(Locale.ROOT), identifierLimit);
        }
    }

    /**
     * Takes one token from the bucket of a key.
     *
     * @param buckets buckets of one kind of key.
     * @param key     the key.
     * @param limit   requests the key may make per window.
     * @throws OttRateLimitExceededException if the bucket is empty.
     */
    private static void consume(final FixedWindowBuckets buckets, final String key, final int limit) {
        final var wait = buckets.tryConsume(key, limit);
        if (wait.isPresent()) {
            throw new OttRateLimitExceededException(wait.get());
        }
    }

    /**
     * Builds the buckets of one kind of key.
     *
     * @param clock source of the current time.
     * @return the buckets.
     */
    private FixedWindowBuckets buckets(final Clock clock) {
        return new FixedWindowBuckets(clock, properties.window(), properties.maxTrackedKeys());
    }
}
// end::ott-rate-limit[]
