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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Unit tests of {@link RecoveryCodesSuccessHandler}.
 */
@ExtendWith(MockitoExtension.class)
class RecoveryCodesSuccessHandlerTest {

    /** Keeps the codes waiting to be shown. */
    @Mock
    private PendingRecoveryCodes pendingRecoveryCodes;

    /** Handler that resumes the interrupted request. */
    @Mock
    private AuthenticationSuccessHandler delegate;

    /** The verified authentication. */
    @Mock
    private Authentication authentication;

    /** Handler under test. */
    private RecoveryCodesSuccessHandler handler;

    /** The request. */
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    /** The response. */
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    /**
     * Builds the handler.
     */
    @BeforeEach
    void setUp() {
        handler = new RecoveryCodesSuccessHandler(pendingRecoveryCodes, delegate);
    }

    /**
     * Verifies that pending codes send the browser to the page that shows them.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenCodesArePending_redirectsToTheRecoveryCodesPage() throws Exception {
        when(pendingRecoveryCodes.isPending(request)).thenReturn(true);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertEquals(RecoveryCodesPageController.RECOVERY_CODES_PATH, response.getRedirectedUrl());
        verifyNoInteractions(delegate);
    }

    /**
     * Verifies that, without pending codes, the delegate resumes the interrupted request.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenNoCodesArePending_delegates() throws Exception {
        when(pendingRecoveryCodes.isPending(request)).thenReturn(false);

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(delegate).onAuthenticationSuccess(request, response, authentication);
    }
}
