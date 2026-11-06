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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Wires the OpenID Connect RP-initiated logout of the BFF. The handler is applied by the logout of the security
 * filter chain ({@code POST /bff/logout}), which redirects the browser to the URL it builds.
 */
@Configuration(proxyBeanMethods = false)
public class LogoutConfiguration {

    /** Where the authorization server sends the browser back after the logout: the root of the SPA. */
    static final String POST_LOGOUT_REDIRECT_URI = "{baseUrl}/";

    // tag::bff-logout-handler[]
    /**
     * Builds the handler that redirects the browser to the logout URL of the authorization server (its
     * {@code end_session_endpoint}, with {@code id_token_hint} and {@code post_logout_redirect_uri}), with the default
     * redirect strategy: the answer to {@code POST /bff/logout} is a {@code 302} that the browser follows as a
     * top-level navigation, so no script ever reads the ID token the URL carries.
     *
     * @param clientRepository the registered OAuth2 clients.
     * @return the logout success handler.
     */
    @Bean
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(
            final ClientRegistrationRepository clientRepository) {
        final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRepository);
        handler.setPostLogoutRedirectUri(POST_LOGOUT_REDIRECT_URI);
        return handler;
    }
    // end::bff-logout-handler[]
}
