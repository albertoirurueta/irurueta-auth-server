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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.x509.X509ChainCustomizer;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/** Unit tests of {@link IdentitiesPageChainCustomizer}. */
class IdentitiesPageChainCustomizerTest {

    /** Manager that applies the multi-factor policy. */
    private final MfaAuthorizationManager authorizationManager = mock(MfaAuthorizationManager.class);

    /** The customizer comes after the X.509 one. */
    @Test
    void order_whenRead_isAfterTheX509Customizer() {
        assertEquals(X509ChainCustomizer.ORDER + 1, IdentitiesPageChainCustomizer.ORDER);
    }

    /** The page and its link post need the multi-factor policy. */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_guardsThePageAndItsPostWithThePolicy() {
        final var http = mock(HttpSecurity.class);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var page = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registry.requestMatchers("/account/identities", "/account/identities/**")).thenReturn(page);

        new IdentitiesPageChainCustomizer(authorizationManager).customize(http);
        captor.getValue().customize(registry);

        verify(page).access(authorizationManager);
    }
}
