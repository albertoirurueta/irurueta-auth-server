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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Unit tests of {@link FederatedOidcUserService}.
 */
@ExtendWith(MockitoExtension.class)
class FederatedOidcUserServiceTest {

    /** Subject of the provider. */
    private static final String SUBJECT = "subject";

    /** E-mail address of the user. */
    private static final String EMAIL = "alice@example.org";

    /** Local username. */
    private static final String USERNAME = "alice";

    /** Issue instant of the test tokens. */
    private static final Instant ISSUED = Instant.parse("2026-01-01T10:00:00Z");

    /** Lifetime of the test tokens, in seconds. */
    private static final long LIFETIME_SECONDS = 600L;

    /** The framework's service. */
    @Mock
    private OAuth2UserService<OidcUserRequest, OidcUser> delegate;

    /** Resolves the local account. */
    @Mock
    private FederatedAccountResolver accountResolver;

    /** Real mapper. */
    @Spy
    private FederatedUserMapper userMapper = new FederatedUserMapper();

    /** Service under test. */
    @InjectMocks
    private FederatedOidcUserService service;

    /**
     * Verifies that a sign-in resolves the account from the provider's subject, the e-mail address and whether it is
     * verified, and answers a principal named after the account with the account's authorities.
     */
    @Test
    void loadUser_whenProviderVerifiedTheEmail_returnsTheLocalPrincipal() {
        final var request = request("google");
        final var upstream = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),
                request.getIdToken());
        when(delegate.loadUser(request)).thenReturn(upstream);
        when(accountResolver.resolve(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true))
                .thenReturn(User.withUsername(USERNAME).password("hash").authorities("ROLE_USER").build());

        final var user = service.loadUser(request);

        assertEquals(USERNAME, user.getName());
        assertEquals(SUBJECT, user.getSubject());
        assertEquals(List.of("ROLE_USER"), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /**
     * Verifies that an unverified address is passed on as such, and that a refusal of the resolver is not caught.
     */
    @Test
    void loadUser_whenResolverRefuses_propagatesTheRefusal() {
        final var request = request("microsoft");
        final var upstream = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("OIDC_USER")),
                request.getIdToken());
        when(delegate.loadUser(request)).thenReturn(upstream);
        final var refusal = new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        when(accountResolver.resolve(IdentityProvider.MICROSOFT, SUBJECT, EMAIL, false)).thenThrow(refusal);

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> service.loadUser(request));

        assertSame(refusal, error);
    }

    /**
     * Verifies that a registration that is not one of the known providers is refused before anything is loaded.
     */
    @Test
    void loadUser_whenProviderIsUnknown_throwsInvalidRequest() {
        final var request = request("facebook");

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> service.loadUser(request));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getError().getErrorCode());
        verifyNoInteractions(delegate, accountResolver);
    }

    /**
     * Builds the request of a registration.
     *
     * @param registrationId registration id.
     * @return the request.
     */
    private static OidcUserRequest request(final String registrationId) {
        final var registration = ClientRegistration.withRegistrationId(registrationId)
                .clientId("client").clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.org/callback")
                .authorizationUri("https://provider.example/authorize")
                .tokenUri("https://provider.example/token").build();
        final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access", ISSUED,
                ISSUED.plusSeconds(LIFETIME_SECONDS));
        final var idToken = new OidcIdToken("id", ISSUED, ISSUED.plusSeconds(LIFETIME_SECONDS),
                Map.of("sub", SUBJECT, "email", EMAIL, "email_verified", "google".equals(registrationId)));
        return new OidcUserRequest(registration, accessToken, idToken);
    }
}
