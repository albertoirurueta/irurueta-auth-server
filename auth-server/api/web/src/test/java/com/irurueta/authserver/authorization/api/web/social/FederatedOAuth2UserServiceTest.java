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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Unit tests of {@link FederatedOAuth2UserService}.
 */
@ExtendWith(MockitoExtension.class)
class FederatedOAuth2UserServiceTest {

    /** Numeric id GitHub assigned. */
    private static final long GITHUB_ID = 42L;

    /** User endpoint of the registration. */
    private static final String USER_URI = "https://api.github.test/user";

    /** Local username. */
    private static final String USERNAME = "alice";

    /** Verified address. */
    private static final String EMAIL = "alice@example.org";

    /** Issue instant of the test token. */
    private static final Instant ISSUED = Instant.parse("2026-01-01T10:00:00Z");

    /** Lifetime of the test token, in seconds. */
    private static final long LIFETIME_SECONDS = 600L;

    /** The framework's service. */
    @Mock
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;

    /** Reads the verified address. */
    @Mock
    private GitHubEmailClient emailClient;

    /** Resolves the local account. */
    @Mock
    private FederatedAccountResolver accountResolver;

    /** Real mapper. */
    @Spy
    private FederatedUserMapper userMapper = new FederatedUserMapper();

    /** Service under test. */
    @InjectMocks
    private FederatedOAuth2UserService service;

    /**
     * Verifies that GitHub's numeric id is the subject, the verified primary address is the e-mail, and the principal
     * is the local one.
     */
    @Test
    void loadUser_whenGitHubHasAVerifiedPrimaryEmail_returnsTheLocalPrincipal() {
        final var request = request("github");
        when(delegate.loadUser(request)).thenReturn(upstream());
        when(emailClient.verifiedPrimaryEmail(USER_URI, "access")).thenReturn(Optional.of(EMAIL));
        when(accountResolver.resolve(IdentityProvider.GITHUB, "42", EMAIL, true))
                .thenReturn(User.withUsername(USERNAME).password("hash").authorities("ROLE_USER").build());

        final var user = service.loadUser(request);

        assertEquals(USERNAME, user.getName());
        assertEquals(EMAIL, user.getAttribute("email"));
        assertEquals("octo", user.getAttribute("login"));
        assertEquals(List.of("ROLE_USER"),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /**
     * Verifies that without a verified address the resolver is told so and the principal has no e-mail.
     */
    @Test
    void loadUser_whenGitHubHasNoVerifiedEmail_resolvesWithAnUnverifiedAddress() {
        final var request = request("github");
        when(delegate.loadUser(request)).thenReturn(upstream());
        when(emailClient.verifiedPrimaryEmail(USER_URI, "access")).thenReturn(Optional.empty());
        when(accountResolver.resolve(IdentityProvider.GITHUB, "42", null, false))
                .thenReturn(User.withUsername(USERNAME).password("hash").authorities("ROLE_USER").build());

        final var user = service.loadUser(request);

        assertFalse(user.getAttributes().containsKey("email"));
    }

    /**
     * Verifies that a registration other than GitHub is refused before anything is loaded.
     */
    @Test
    void loadUser_whenRegistrationIsNotGitHub_throwsInvalidRequest() {
        final var request = request("google");

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> service.loadUser(request));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getError().getErrorCode());
        verifyNoInteractions(delegate, emailClient, accountResolver);
    }

    /**
     * Builds the user GitHub's API describes.
     *
     * @return the user.
     */
    private static OAuth2User upstream() {
        return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("OAUTH2_USER")),
                Map.of("id", GITHUB_ID, "login", "octo", "email", "unverified@example.org"), "id");
    }

    /**
     * Builds the request of a registration.
     *
     * @param registrationId registration id.
     * @return the request.
     */
    private static OAuth2UserRequest request(final String registrationId) {
        final var registration = ClientRegistration.withRegistrationId(registrationId)
                .clientId("client").clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.org/callback")
                .authorizationUri("https://provider.example/authorize")
                .tokenUri("https://provider.example/token")
                .userInfoUri(USER_URI).userNameAttributeName("id").build();
        return new OAuth2UserRequest(registration, new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access",
                ISSUED, ISSUED.plusSeconds(LIFETIME_SECONDS)));
    }
}
