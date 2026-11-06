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

package com.irurueta.authserver.resourceserver.api.web.security;

import java.time.Clock;
import java.time.Instant;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Requires that the bearer token proves a recent strong authentication (RFC 9470): its {@code acr} claim must be
 * the configured one and its {@code auth_time} claim no older than the configured maximum age. The claims are read
 * from the token attributes, so it serves JWTs (their claims) and opaque tokens (the introspection answer) alike.
 *
 * <p>A caller without the {@code requiredAuthority} is denied with an ordinary decision (answered
 * {@code 403 insufficient_scope}); a caller that has it but fails the step-up check is denied with a
 * {@link StepUpRequiredDecision}, which {@link StepUpAccessDeniedHandler} answers with the RFC 9470 challenge.
 */
// tag::resource-server-step-up[]
@RequiredArgsConstructor
public class StepUpAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    /** Claim carrying the authentication context class reference. */
    static final String ACR_CLAIM = "acr";

    /** Claim carrying the time of the user's authentication, in epoch seconds. */
    static final String AUTH_TIME_CLAIM = "auth_time";

    /** Authority the caller needs before the step-up requirement is evaluated. */
    private final String requiredAuthority;

    /** Step-up policy. */
    private final StepUpProperties properties;

    /** Source of the current time. */
    private final Clock clock;

    @Override
    public AuthorizationResult authorize(final Supplier<? extends Authentication> authentication,
            final RequestAuthorizationContext context) {
        final var current = authentication.get();
        if (current == null || !current.isAuthenticated() || current.getAuthorities().stream()
                .noneMatch(authority -> requiredAuthority.equals(authority.getAuthority()))) {
            return new AuthorizationDecision(false);
        }
        if (!properties.enabled() || satisfied(current)) {
            return new AuthorizationDecision(true);
        }
        return new StepUpRequiredDecision();
    }

    /**
     * Tells whether the token proves the required authentication.
     *
     * @param authentication the authenticated bearer token.
     * @return {@code true} when the {@code acr} matches and {@code auth_time} is recent enough.
     */
    private boolean satisfied(final Authentication authentication) {
        if (!(authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> token)) {
            return false;
        }
        final var attributes = token.getTokenAttributes();
        if (!properties.acrValues().equals(attributes.get(ACR_CLAIM))) {
            return false;
        }
        final var authenticatedAt = toInstant(attributes.get(AUTH_TIME_CLAIM));
        return authenticatedAt != null
                && !authenticatedAt.plus(properties.maxAge()).isBefore(clock.instant());
    }

    /**
     * Converts an {@code auth_time} value, which is epoch seconds in a JWT or an introspection answer.
     *
     * @param value the claim value.
     * @return the instant, or {@code null} when the value is missing or of an unexpected type.
     */
    private static Instant toInstant(final Object value) {
        return switch (value) {
            case Instant instant -> instant;
            case Number number -> Instant.ofEpochSecond(number.longValue());
            case null, default -> null;
        };
    }
}
// end::resource-server-step-up[]
