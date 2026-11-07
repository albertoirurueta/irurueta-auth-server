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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Unit tests of {@link PasskeyRegistrationAuthorizationManager}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyRegistrationAuthorizationManagerTest {

    /** Manager that applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager mfaAuthorizationManager;

    /** Authentication of the request. */
    @Mock
    private Authentication authentication;

    /** Manager under test. */
    @InjectMocks
    private PasskeyRegistrationAuthorizationManager manager;

    /**
     * Verifies that every registration endpoint, whatever its method, is decided by the multi-factor policy.
     *
     * @param path path of the request.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/webauthn/register", "/webauthn/register/options", "/webauthn/register/abc"})
    void authorize_whenRequestIsARegistrationEndpoint_returnsTheDecisionOfThePolicy(final String path) {
        final var refused = new AuthorizationDecision(false);
        final Supplier<Authentication> supplier = () -> authentication;
        when(mfaAuthorizationManager.authorize(eq(supplier), any(RequestAuthorizationContext.class)))
                .thenReturn(refused);

        final var result = manager.authorize(supplier, new MockHttpServletRequest("POST", path));

        assertSame(refused, result);
    }

    /**
     * Verifies that other requests are not decided here.
     *
     * @param path path of the request.
     */
    @ParameterizedTest
    @ValueSource(strings = {"/login/webauthn", "/webauthn/authenticate/options", "/login", "/webauthn/registerx"})
    void authorize_whenRequestIsNotARegistrationEndpoint_grantsWithoutAskingThePolicy(final String path) {
        final var result = manager.authorize(() -> authentication, new MockHttpServletRequest("POST", path));

        assertTrue(result.isGranted());
        verifyNoInteractions(mfaAuthorizationManager);
    }

    /**
     * Verifies that the path constant is the one of the framework's registration endpoints.
     */
    @Test
    void registrationPath_whenRead_isTheFrameworkPath() {
        assertSame("/webauthn/register", PasskeyRegistrationAuthorizationManager.REGISTRATION_PATH);
    }
}
