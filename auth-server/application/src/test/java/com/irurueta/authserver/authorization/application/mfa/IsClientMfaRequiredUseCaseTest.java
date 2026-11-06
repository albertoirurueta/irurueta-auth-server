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

package com.irurueta.authserver.authorization.application.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link IsClientMfaRequiredUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class IsClientMfaRequiredUseCaseTest {

    /** Identifier of the client. */
    private static final String CLIENT_ID = "client";

    /** Port that stores the clients. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** A registered client. */
    @Mock
    private ClientRegistration registration;

    /** Use case under test. */
    @InjectMocks
    private IsClientMfaRequiredUseCase useCase;

    /**
     * Verifies that a client that requires a second factor is reported as such.
     */
    @Test
    void execute_whenClientRequiresMfa_returnsTrue() {
        when(clientRegistrationRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(registration));
        when(registration.mfaRequired()).thenReturn(true);

        assertTrue(useCase.execute(CLIENT_ID));
    }

    /**
     * Verifies that a client that does not require a second factor is reported as such.
     */
    @Test
    void execute_whenClientDoesNotRequireMfa_returnsFalse() {
        when(clientRegistrationRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(registration));
        when(registration.mfaRequired()).thenReturn(false);

        assertFalse(useCase.execute(CLIENT_ID));
    }

    /**
     * Verifies that an unknown client requires nothing.
     */
    @Test
    void execute_whenClientIsUnknown_returnsFalse() {
        when(clientRegistrationRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());

        assertFalse(useCase.execute(CLIENT_ID));
    }

    /**
     * Verifies that a request naming no client requires nothing and looks nothing up.
     */
    @Test
    void execute_whenClientIdIsNull_returnsFalse() {
        assertFalse(useCase.execute(null));
        verifyNoInteractions(clientRegistrationRepository);
    }
}
