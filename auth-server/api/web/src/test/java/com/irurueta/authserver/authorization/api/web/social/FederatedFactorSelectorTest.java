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

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/**
 * Unit tests of {@link FederatedFactorSelector}.
 */
class FederatedFactorSelectorTest {

    /** Secret of the tests, never a real one. */
    private static final String SECRET = "not-a-secret";

    /** Selector under test, with Google trusted and GitHub not. */
    private final FederatedFactorSelector selector = new FederatedFactorSelector(new SocialProperties(Map.of(
            "google", new SocialProperties.Provider("id", SECRET, true, null, null, null, null, null, null),
            "github", new SocialProperties.Provider("id", SECRET, false, null, null, null, null, null, null))),
            new FederatedUserMapper());

    /**
     * Verifies that a trusted provider that reports {@code mfa} gets the strong factor.
     */
    @Test
    void authorityOf_whenTrustedProviderReportsMfa_isTheStrongFactor() {
        assertEquals(FederatedFactor.STRONG_AUTHORITY, selector.authorityOf(token("google", List.of("pwd", "mfa"))));
    }

    /**
     * Verifies that a trusted provider that does not report {@code mfa} gets the ordinary factor.
     */
    @Test
    void authorityOf_whenTrustedProviderDoesNotReportMfa_isTheOrdinaryFactor() {
        assertEquals(FederatedFactor.AUTHORITY, selector.authorityOf(token("google", List.of("pwd"))));
    }

    /**
     * Verifies that a provider that is not trusted gets the ordinary factor whatever it claims.
     */
    @Test
    void authorityOf_whenProviderIsNotTrusted_isTheOrdinaryFactorWhateverItClaims() {
        assertEquals(FederatedFactor.AUTHORITY, selector.authorityOf(token("github", List.of("mfa"))));
    }

    /**
     * Verifies that a registration that is not a known provider gets the ordinary factor.
     */
    @Test
    void authorityOf_whenRegistrationIsUnknown_isTheOrdinaryFactor() {
        assertEquals(FederatedFactor.AUTHORITY, selector.authorityOf(token("facebook", List.of("mfa"))));
    }

    /**
     * Builds the authentication of a sign-in.
     *
     * @param registrationId registration id.
     * @param amr            upstream methods.
     * @return the authentication.
     */
    private static OAuth2AuthenticationToken token(final String registrationId, final List<String> amr) {
        final var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("amr", amr, "name", "alice"), "name");
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), registrationId);
    }
}
