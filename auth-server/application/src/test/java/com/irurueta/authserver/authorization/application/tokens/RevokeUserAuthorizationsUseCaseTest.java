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

package com.irurueta.authserver.authorization.application.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.tokens.UserAuthorizationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RevokeUserAuthorizationsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RevokeUserAuthorizationsUseCaseTest {

    /** Number of authorizations the mocked port reports as deleted. */
    private static final int DELETED = 3;

    /** Port that removes stored authorizations. */
    @Mock
    private UserAuthorizationRepository userAuthorizationRepository;

    /** Use case under test. */
    @InjectMocks
    private RevokeUserAuthorizationsUseCase useCase;

    /**
     * Verifies that the authorizations of the user are deleted.
     */
    @Test
    void execute_whenCalled_deletesTheAuthorizationsOfTheUser() {
        when(userAuthorizationRepository.deleteByPrincipalName("alice")).thenReturn(DELETED);

        assertEquals(DELETED, useCase.execute("alice"));
    }
}
