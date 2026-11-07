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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.passkeys.PasskeyProperties;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Unit tests of {@link PasskeyChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyChainCustomizerTest {

    /** Name of the relying party. */
    private static final String RP_NAME = "Test server";

    /** Identifier of the relying party. */
    private static final String RP_ID = "localhost";

    /** Origin the ceremonies may run from. */
    private static final String ORIGIN = "http://localhost:9000";

    /** Manager that applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Loads the accounts. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Resolves the account of the signed-in user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Tells whether the second factor of a user is locked. */
    @Mock
    private CheckSecondFactorLockoutUseCase lockoutUseCase;

    /**
     * Verifies the rules of the chain: the script and the public endpoints are open, the framework's removal of a
     * credential is denied and the account page needs the multi-factor policy.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_permitsPublicEndpointsDeniesRemovalAndGuardsTheAccountPage() {
        final var http = mock(HttpSecurity.class);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var open = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        final var removal = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        final var page = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registry.requestMatchers("/js/passkeys.js", "/webauthn/authenticate/options", "/login/webauthn"))
                .thenReturn(open);
        when(open.permitAll()).thenReturn(registry);
        when(registry.requestMatchers(HttpMethod.DELETE, "/webauthn/register/**")).thenReturn(removal);
        when(removal.denyAll()).thenReturn(registry);
        when(registry.requestMatchers("/account/passkeys")).thenReturn(page);

        customizer().customize(http);
        captor.getValue().customize(registry);

        verify(open).permitAll();
        verify(removal).denyAll();
        verify(page).access(authorizationManager);
    }

    /**
     * Verifies that the registration guard is installed before the chain's authorization filter, that the lockout
     * filter is installed where the WebAuthn authentication filter will be, before it, that the user
     * service that refuses disabled accounts is the one the WebAuthn configurer will find, and that the configurer
     * is given the relying party, the origins, no default registration page and the session strategy hook.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_installsTheGuardTheUserServiceAndTheWebAuthnConfiguration() {
        final var http = mock(HttpSecurity.class);
        final var webAuthnCaptor = ArgumentCaptor.<Customizer<WebAuthnConfigurer<HttpSecurity>>>captor();
        when(http.webAuthn(webAuthnCaptor.capture())).thenReturn(http);
        final var configurer = mock(WebAuthnConfigurer.class, RETURNS_SELF);

        customizer().customize(http);
        webAuthnCaptor.getValue().customize(configurer);

        verify(http).addFilterBefore(any(PasskeyRegistrationFilter.class), eq(AuthorizationFilter.class));
        verify(http).addFilterBefore(any(PasskeySecondFactorLockoutFilter.class),
                eq(BasicAuthenticationFilter.class));
        final var userDetailsCaptor = ArgumentCaptor.<UserDetailsService>captor();
        verify(http).setSharedObject(eq(UserDetailsService.class), userDetailsCaptor.capture());
        assertInstanceOf(AccountStatusUserDetailsService.class, userDetailsCaptor.getValue());
        verify(configurer).rpName(RP_NAME);
        verify(configurer).rpId(RP_ID);
        verify(configurer).allowedOrigins(Set.of(ORIGIN));
        verify(configurer).disableDefaultRegistrationPage(true);
        verify(configurer).addObjectPostProcessor(any(SessionStrategyPostProcessor.class));
    }

    /**
     * Verifies the paths the customizer works with.
     */
    @Test
    void constants_whenRead_areThePathsOfTheWebAuthnEndpointsAndTheScript() {
        assertEquals("/js/passkeys.js", PasskeyChainCustomizer.SCRIPT_PATH);
        assertEquals("/webauthn/authenticate/options", PasskeyChainCustomizer.AUTHENTICATION_OPTIONS_PATH);
        assertEquals("/login/webauthn", PasskeyChainCustomizer.AUTHENTICATION_PATH);
    }

    /**
     * Builds the customizer under test.
     *
     * @return the customizer.
     */
    private PasskeyChainCustomizer customizer() {
        return new PasskeyChainCustomizer(new PasskeyProperties(RP_NAME, RP_ID, List.of(ORIGIN)),
                authorizationManager, userDetailsService, userResolver, lockoutUseCase);
    }
}
