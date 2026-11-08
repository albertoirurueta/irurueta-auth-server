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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.api.web.mfa.FactorTimeline;
import com.irurueta.authserver.authorization.api.web.mfa.MfaClaimsContributor;
import com.irurueta.authserver.authorization.api.web.mfa.PasswordFactor;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * Unit tests of {@link IdpClaimsContributor}, alone and after the real {@link MfaClaimsContributor} over a real
 * {@link FactorTimeline}, which is how the tokens are built.
 */
class IdpClaimsContributorTest {

    /** Authority of the TOTP factor. */
    private static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    /** The instant the federated sign-in happened. */
    private static final Instant SIGN_IN = Instant.parse("2026-01-01T10:00:00Z");

    /** The instant the second factor was presented. */
    private static final Instant SECOND = Instant.parse("2026-01-01T10:01:00Z");

    /** Contributor under test. */
    private final IdpClaimsContributor contributor = new IdpClaimsContributor(new FederatedUserMapper());

    /** Contributor of the multi-factor claims, which runs before. */
    private MfaClaimsContributor mfaContributor;

    /**
     * Creates the multi-factor contributor over a registry with the federated, password and TOTP factors.
     */
    @BeforeEach
    void setUp() {
        final var declarations = new FederatedFactor();
        final var registry = new AuthenticationFactorRegistry(List.of(
                new PasswordFactor().passwordAuthenticationFactor(),
                new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND),
                declarations.federatedAuthenticationFactor(), declarations.federatedStrongAuthenticationFactor()));
        mfaContributor = new MfaClaimsContributor(new FactorTimeline(registry, new MfaPolicy()));
    }

    /**
     * Verifies that an ordinary federated sign-in gets the provider and is a single factor: the upstream methods are
     * not copied, however they read.
     */
    @Test
    void contribute_whenSignInIsOrdinary_addsTheProviderAndNoUpstreamMethods() {
        final var claims = new HashMap<String, Object>();
        final var context = context(token(List.of("pwd", "mfa"), factor(FederatedFactor.AUTHORITY, SIGN_IN)));

        mfaContributor.contribute(context, claims);
        contributor.contribute(context, claims);

        assertEquals("google", claims.get(IdpClaimsContributor.IDP_CLAIM));
        assertEquals(List.of("fed"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.PASSWORD, claims.get(IdTokenClaimNames.ACR));
    }

    /**
     * Verifies that an ordinary federated sign-in followed by a second factor reads {@code fed}, {@code otp} and
     * {@code mfa}, each once.
     */
    @Test
    void contribute_whenOrdinarySignInIsFollowedBySecondFactor_listsEachValueOnce() {
        final var claims = new HashMap<String, Object>();
        final var context = context(token(List.of("pwd"), factor(FederatedFactor.AUTHORITY, SIGN_IN),
                factor(TOTP_AUTHORITY, SECOND)));

        mfaContributor.contribute(context, claims);
        contributor.contribute(context, claims);

        assertEquals(List.of("fed", "otp", "mfa"), claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, claims.get(IdTokenClaimNames.ACR));
    }

    /**
     * Verifies that a strong sign-in, multi-factor alone, gets {@code mfa} and the multi-factor class from the
     * multi-factor contributor, and that the upstream methods are then added once each (the {@code fed} and
     * {@code mfa} the provider repeated, too), in a mutable list.
     */
    @Test
    void contribute_whenSignInIsStrong_mergesTheUpstreamMethodsOnceAndReportsMultiFactor() {
        final var claims = new HashMap<String, Object>();
        final var context = context(token(List.of("pwd", "mfa", "pwd", "fed"),
                factor(FederatedFactor.STRONG_AUTHORITY, SIGN_IN)));

        mfaContributor.contribute(context, claims);
        contributor.contribute(context, claims);

        assertEquals(List.of("fed", "mfa", "pwd"), claims.get(IdTokenClaimNames.AMR));
        assertInstanceOf(ArrayList.class, claims.get(IdTokenClaimNames.AMR));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, claims.get(IdTokenClaimNames.ACR));
        assertEquals("google", claims.get(IdpClaimsContributor.IDP_CLAIM));
    }

    /**
     * Verifies that a strong sign-in whose claims have no {@code amr} yet still gets one, and that this contributor
     * never sets {@code acr} itself: the multi-factor contributor owns it.
     */
    @Test
    void contribute_whenSignInIsStrongAndClaimsHaveNoAmr_createsItWithoutAcr() {
        final var claims = new HashMap<String, Object>();
        final var context = context(token(List.of("mfa"), factor(FederatedFactor.STRONG_AUTHORITY, SIGN_IN)));

        contributor.contribute(context, claims);

        assertEquals(List.of("mfa"), claims.get(IdTokenClaimNames.AMR));
        assertFalse(claims.containsKey(IdTokenClaimNames.ACR));
    }

    /**
     * Verifies that a token of another kind of sign-in gets nothing.
     */
    @Test
    void contribute_whenPrincipalIsNotAFederatedSignIn_addsNothing() {
        final var claims = new HashMap<String, Object>();

        contributor.contribute(context(new TestingAuthenticationToken("bob", "secret", "ROLE_USER")), claims);
        contributor.contribute(mock(OAuth2TokenContext.class), claims);

        assertTrue(claims.isEmpty());
        assertFalse(claims.containsKey(IdpClaimsContributor.IDP_CLAIM));
    }

    /**
     * Verifies the position of the contributor: after the multi-factor one it extends.
     */
    @Test
    void order_whenRead_isAfterTheMultiFactorContributor() {
        assertEquals(IdpClaimsContributor.ORDER, IdpClaimsContributor.class.getAnnotation(Order.class).value());
        assertTrue(IdpClaimsContributor.ORDER > MfaClaimsContributor.ORDER);
    }

    /**
     * Builds the authentication of a federated sign-in.
     *
     * @param amr       upstream methods.
     * @param authority factor authorities of the session.
     * @return the authentication.
     */
    private static OAuth2AuthenticationToken token(final List<String> amr, final GrantedAuthority... authority) {
        final var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("amr", new ArrayList<>(amr), "local_username", "alice"), "local_username");
        final var authorities = new ArrayList<GrantedAuthority>(user.getAuthorities());
        authorities.addAll(List.of(authority));
        return new OAuth2AuthenticationToken(user, authorities, "google");
    }

    /**
     * Builds a factor authority.
     *
     * @param authority authority of the factor.
     * @param issuedAt  instant it was granted.
     * @return the authority.
     */
    private static FactorGrantedAuthority factor(final String authority, final Instant issuedAt) {
        return FactorGrantedAuthority.withAuthority(authority).issuedAt(issuedAt).build();
    }

    /**
     * Builds a token context of a principal.
     *
     * @param principal the principal.
     * @return the context.
     */
    private static OAuth2TokenContext context(final Authentication principal) {
        final var context = mock(OAuth2TokenContext.class);
        when(context.getPrincipal()).thenReturn(principal);
        return context;
    }
}
