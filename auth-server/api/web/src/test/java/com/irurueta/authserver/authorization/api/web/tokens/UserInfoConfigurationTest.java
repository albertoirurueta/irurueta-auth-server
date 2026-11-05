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

package com.irurueta.authserver.authorization.api.web.tokens;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcUserInfoEndpointConfigurer;

/**
 * Unit tests of {@link UserInfoConfiguration}.
 */
class UserInfoConfigurationTest {

    /**
     * The customizer installs the mapper in the UserInfo endpoint.
     */
    @Test
    void userInfoProtocolChainCustomizer_whenApplied_registersMapper() {
        final var mapper = mock(UserInfoMapper.class);
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var oidc = mock(OidcConfigurer.class);
        final var endpoint = mock(OidcUserInfoEndpointConfigurer.class);
        final var oidcCaptor = ArgumentCaptor.<Customizer<OidcConfigurer>>captor();
        final var endpointCaptor = ArgumentCaptor.<Customizer<OidcUserInfoEndpointConfigurer>>captor();

        new UserInfoConfiguration().userInfoProtocolChainCustomizer(mapper).customize(server);
        verify(server).oidc(oidcCaptor.capture());
        oidcCaptor.getValue().customize(oidc);
        verify(oidc).userInfoEndpoint(endpointCaptor.capture());
        endpointCaptor.getValue().customize(endpoint);

        verify(endpoint).userInfoMapper(mapper);
    }
}
