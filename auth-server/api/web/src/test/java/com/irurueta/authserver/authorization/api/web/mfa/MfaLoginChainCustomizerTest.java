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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Unit tests of {@link MfaLoginChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class MfaLoginChainCustomizerTest {

    /** TOTP authority. */
    private static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    /** Manager that applies the policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Entry point of the second-factor page. */
    @Mock
    private AuthenticationEntryPoint entryPoint;

    /**
     * Verifies that the consent page is guarded by the manager and that every second factor is mapped to the entry
     * point of the second-factor page.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_guardsConsentAndMapsMissingSecondFactorsToEntryPoint() {
        final var registry = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY),
                new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND)));
        final var customizer = new MfaLoginChainCustomizer(authorizationManager, registry, entryPoint);
        final var http = mock(HttpSecurity.class);
        final var authorizeCaptor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        final var exceptionsCaptor = ArgumentCaptor.<Customizer<ExceptionHandlingConfigurer<HttpSecurity>>>captor();
        when(http.authorizeHttpRequests(authorizeCaptor.capture())).thenReturn(http);
        when(http.exceptionHandling(exceptionsCaptor.capture())).thenReturn(http);
        final var registryMock = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var authorizedUrl = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registryMock.requestMatchers(any(String[].class))).thenReturn(authorizedUrl);
        final var exceptions = mock(ExceptionHandlingConfigurer.class);

        customizer.customize(http);
        authorizeCaptor.getValue().customize(registryMock);
        exceptionsCaptor.getValue().customize(exceptions);

        verify(registryMock).requestMatchers("/oauth2/consent");
        verify(authorizedUrl).access(authorizationManager);
        verify(exceptions).defaultDeniedHandlerForMissingAuthority(entryPoint, TOTP_AUTHORITY);
    }
}
