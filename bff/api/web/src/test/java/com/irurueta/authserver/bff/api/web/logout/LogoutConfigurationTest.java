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

package com.irurueta.authserver.bff.api.web.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * Unit tests of {@link LogoutConfiguration}.
 */
class LogoutConfigurationTest {

    /** Registration id of the BFF client. */
    private static final String REGISTRATION_ID = "bff";

    /** End session endpoint of the authorization server. */
    private static final String END_SESSION_ENDPOINT = "http://localhost:9000/connect/logout";

    /** Value of the test ID token; not a real token. */
    private static final String ID_TOKEN_VALUE = "test-id-token";

    /**
     * Verifies that, with a principal that is not an OIDC login, the handler redirects the browser to its default
     * target, the root of the application.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void oidcLogoutSuccessHandler_whenPrincipalIsNotOidc_redirectsToRoot() throws Exception {
        final var handler = new LogoutConfiguration().oidcLogoutSuccessHandler(
                mock(ClientRegistrationRepository.class));
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals(HttpStatus.FOUND.value(), response.getStatus());
        assertEquals("/", response.getRedirectedUrl());
    }

    /**
     * Verifies that, for an OIDC login, the handler redirects the browser itself to the end session endpoint with the
     * ID token hint and the root of the application as post-logout redirect URI.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void oidcLogoutSuccessHandler_whenPrincipalIsOidc_redirectsToEndSessionEndpoint() throws Exception {
        final var registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientId(REGISTRATION_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .tokenUri("http://localhost:9000/oauth2/token")
                .providerConfigurationMetadata(Map.of("end_session_endpoint", END_SESSION_ENDPOINT))
                .build();
        final var repository = mock(ClientRegistrationRepository.class);
        when(repository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
        final var handler = new LogoutConfiguration().oidcLogoutSuccessHandler(repository);
        final var idToken = OidcIdToken.withTokenValue(ID_TOKEN_VALUE).subject("demo").build();
        final var user = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"), idToken);
        final var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), REGISTRATION_ID);
        final var request = new MockHttpServletRequest("POST", "/bff/logout");
        final var response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, authentication);

        assertEquals(HttpStatus.FOUND.value(), response.getStatus());
        final var location = response.getRedirectedUrl();
        assertTrue(location.startsWith(END_SESSION_ENDPOINT + "?"), location);
        assertTrue(location.contains("id_token_hint=" + ID_TOKEN_VALUE), location);
        assertTrue(location.contains("post_logout_redirect_uri=http://localhost/"), location);
    }
}
