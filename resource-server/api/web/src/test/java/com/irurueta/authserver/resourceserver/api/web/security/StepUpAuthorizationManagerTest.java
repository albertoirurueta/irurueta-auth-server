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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/** Unit tests for {@link StepUpAuthorizationManager}. */
class StepUpAuthorizationManagerTest {

    /** Authority the manager needs before evaluating the step-up. */
    private static final String AUTHORITY = "SCOPE_documents.delete";

    /** Required acr. */
    private static final String MFA = "urn:irurueta:acr:mfa";

    /** A second acceptable acr. */
    private static final String PHISHING_RESISTANT = "urn:irurueta:acr:phr";

    /** Maximum age of the authentication. */
    private static final Duration MAX_AGE = Duration.ofMinutes(5);

    /** The instant "now" of the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

    /** Seconds in a minute. */
    private static final long MINUTE = 60;

    /** Fixed clock. */
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    /** Subject under test. */
    private final StepUpAuthorizationManager manager = new StepUpAuthorizationManager(AUTHORITY,
            new StepUpProperties(true, MFA, MAX_AGE), clock);

    /** A JWT with the acr and a recent auth_time is granted. */
    @Test
    void authorize_whenJwtIsStrongAndRecent_grants() {
        assertTrue(manager.authorize(() -> jwt(MFA, NOW.getEpochSecond() - MINUTE), null).isGranted());
    }

    /** The age limit is inclusive. */
    @Test
    void authorize_whenAuthenticationIsExactlyMaxAgeOld_grants() {
        assertTrue(manager.authorize(() -> jwt(MFA, NOW.minus(MAX_AGE).getEpochSecond()), null).isGranted());
    }

    /** An old authentication requires step-up. */
    @Test
    void authorize_whenAuthenticationIsTooOld_requiresStepUp() {
        assertStepUp(manager.authorize(() -> jwt(MFA, NOW.minus(MAX_AGE).getEpochSecond() - 1), null));
    }

    /** A password-level acr requires step-up. */
    @Test
    void authorize_whenAcrIsPassword_requiresStepUp() {
        assertStepUp(manager.authorize(() -> jwt("urn:irurueta:acr:pwd", NOW.getEpochSecond()), null));
    }

    /** A token without acr requires step-up. */
    @Test
    void authorize_whenAcrIsMissing_requiresStepUp() {
        assertStepUp(manager.authorize(() -> jwt(null, NOW.getEpochSecond()), null));
    }

    /** A token without auth_time requires step-up. */
    @Test
    void authorize_whenAuthTimeIsMissing_requiresStepUp() {
        assertStepUp(manager.authorize(() -> jwt(MFA, null), null));
    }

    /** An auth_time of an unexpected type requires step-up. */
    @Test
    void authorize_whenAuthTimeIsNotANumber_requiresStepUp() {
        assertStepUp(manager.authorize(() -> jwt(MFA, "yesterday"), null));
    }

    /** An auth_time given as an instant is understood (opaque attributes). */
    @Test
    void authorize_whenAuthTimeIsAnInstant_grants() {
        assertTrue(manager.authorize(() -> opaque(MFA, NOW.minusSeconds(MINUTE)), null).isGranted());
    }

    /** The opaque variant reads the introspection attributes. */
    @Test
    void authorize_whenOpaqueTokenIsStrongAndRecent_grants() {
        assertTrue(manager.authorize(() -> opaque(MFA, NOW.getEpochSecond() - MINUTE), null).isGranted());
    }

    /** The opaque variant requires step-up too. */
    @Test
    void authorize_whenOpaqueTokenIsWeak_requiresStepUp() {
        assertStepUp(manager.authorize(() -> opaque("urn:irurueta:acr:pwd", NOW.getEpochSecond()), null));
    }

    /** Without the scope the denial is ordinary (insufficient scope), whatever the claims. */
    @Test
    void authorize_whenScopeIsMissing_deniesWithoutStepUp() {
        final var token = new TestingAuthenticationToken("alice", "n/a", "SCOPE_documents.read");
        token.setAuthenticated(true);

        final var result = manager.authorize(() -> token, null);

        assertFalse(result.isGranted());
        assertFalse(result instanceof StepUpRequiredDecision);
    }

    /** Without authentication the denial is ordinary. */
    @Test
    void authorize_whenAuthenticationIsNull_deniesWithoutStepUp() {
        final var result = manager.authorize(() -> null, null);

        assertFalse(result.isGranted());
        assertFalse(result instanceof StepUpRequiredDecision);
    }

    /** A non-bearer authentication with the scope cannot prove step-up. */
    @Test
    void authorize_whenAuthenticationIsNotABearerToken_requiresStepUp() {
        final var token = new TestingAuthenticationToken("alice", "n/a", AUTHORITY);

        assertStepUp(manager.authorize(() -> token, null));
    }

    /** With two configured values, a token carrying either of them is granted. */
    @Test
    void authorize_whenSeveralAcrValuesAreConfigured_grantsEachOfThem() {
        final var several = new StepUpAuthorizationManager(AUTHORITY,
                new StepUpProperties(true, " " + MFA + "  " + PHISHING_RESISTANT + " ", MAX_AGE), clock);

        assertTrue(several.authorize(() -> jwt(MFA, NOW.getEpochSecond()), null).isGranted());
        assertTrue(several.authorize(() -> jwt(PHISHING_RESISTANT, NOW.getEpochSecond()), null).isGranted());
    }

    /** With two configured values, a token carrying neither, or the whole list, requires step-up. */
    @Test
    void authorize_whenSeveralAcrValuesAreConfiguredAndAcrIsNotListed_requiresStepUp() {
        final var configured = MFA + " " + PHISHING_RESISTANT;
        final var several = new StepUpAuthorizationManager(AUTHORITY,
                new StepUpProperties(true, configured, MAX_AGE), clock);

        assertStepUp(several.authorize(() -> jwt("urn:irurueta:acr:pwd", NOW.getEpochSecond()), null));
        assertStepUp(several.authorize(() -> jwt(configured, NOW.getEpochSecond()), null));
    }

    /** When disabled the manager only checks the scope. */
    @Test
    void authorize_whenDisabled_grantsWithoutClaims() {
        final var disabled = new StepUpAuthorizationManager(AUTHORITY, new StepUpProperties(false, MFA, MAX_AGE),
                clock);

        assertTrue(disabled.authorize(() -> jwt(null, null), null).isGranted());
    }

    /**
     * Asserts that the result is the step-up requirement.
     *
     * @param result the result.
     */
    private static void assertStepUp(final AuthorizationResult result) {
        assertInstanceOf(StepUpRequiredDecision.class, result);
    }

    /**
     * Builds a JWT authentication holding the delete scope.
     *
     * @param acr      value of the acr claim; {@code null} to leave it out.
     * @param authTime value of the auth_time claim; {@code null} to leave it out.
     * @return the authentication.
     */
    private static Authentication jwt(final String acr, final Object authTime) {
        final var builder = Jwt.withTokenValue("token").header("alg", "none").subject("alice")
                .issuedAt(NOW.minusSeconds(MINUTE)).expiresAt(NOW.plusSeconds(MINUTE));
        if (acr != null) {
            builder.claim("acr", acr);
        }
        if (authTime != null) {
            builder.claim("auth_time", authTime);
        }
        return new JwtAuthenticationToken(builder.build(), List.of(new SimpleGrantedAuthority(AUTHORITY)));
    }

    /**
     * Builds an opaque-token authentication holding the delete scope.
     *
     * @param acr      value of the acr attribute.
     * @param authTime value of the auth_time attribute.
     * @return the authentication.
     */
    private static Authentication opaque(final String acr, final Object authTime) {
        final var authorities = List.<GrantedAuthority>of(new SimpleGrantedAuthority(AUTHORITY));
        final var principal = new DefaultOAuth2AuthenticatedPrincipal("alice",
                Map.of("acr", acr, "auth_time", authTime), authorities);
        final var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token", NOW.minusSeconds(MINUTE),
                NOW.plusSeconds(MINUTE));
        return new BearerTokenAuthentication(principal, token, authorities);
    }
}
