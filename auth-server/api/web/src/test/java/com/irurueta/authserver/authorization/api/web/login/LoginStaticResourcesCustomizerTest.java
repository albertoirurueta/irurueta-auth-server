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

package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Unit tests of {@link LoginStaticResourcesCustomizer}.
 */
class LoginStaticResourcesCustomizerTest {

    /**
     * Verifies that the shared stylesheet path is permitted.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_permitsTheStylesheet() {
        final var http = mock(HttpSecurity.class);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var authorized = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        when(registry.requestMatchers(any(String[].class))).thenReturn(authorized);

        new LoginStaticResourcesCustomizer().customize(http);
        captor.getValue().customize(registry);

        verify(registry).requestMatchers(LoginStaticResourcesCustomizer.STYLESHEET_PATH);
        verify(authorized).permitAll();
        assertEquals("/css/pages.css", LoginStaticResourcesCustomizer.STYLESHEET_PATH);
    }
}
