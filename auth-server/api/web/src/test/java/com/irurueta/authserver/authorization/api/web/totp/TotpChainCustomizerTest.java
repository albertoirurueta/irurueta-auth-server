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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceFilter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * Unit tests of {@link TotpChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class TotpChainCustomizerTest {

    /** Filter that recognises a trusted device. */
    @Mock
    private TrustedDeviceFilter trustedDeviceFilter;

    /** Filter that processes the post of the forms. */
    @Mock
    private TotpAuthenticationFilter totpAuthenticationFilter;

    /**
     * Verifies that the page and the post are open to signed-in users only, and that both filters are installed.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_requiresSignInForTheEndpointsAndAddsTheFilters() {
        final var customizer = new TotpChainCustomizer(trustedDeviceFilter, totpAuthenticationFilter);
        final var http = mock(HttpSecurity.class);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var authorizedUrl = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registry.requestMatchers(any(String[].class))).thenReturn(authorizedUrl);

        customizer.customize(http);
        captor.getValue().customize(registry);

        verify(registry).requestMatchers("/login/second-factor", "/login/second-factor/totp");
        verify(authorizedUrl).authenticated();
        verify(http).addFilterBefore(trustedDeviceFilter, AuthorizationFilter.class);
        verify(http).addFilterBefore(totpAuthenticationFilter, AuthorizationFilter.class);
    }
}
