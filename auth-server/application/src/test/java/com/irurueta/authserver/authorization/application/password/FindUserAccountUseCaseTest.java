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

package com.irurueta.authserver.authorization.application.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link FindUserAccountUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class FindUserAccountUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Port that provides the user accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private FindUserAccountUseCase useCase;

    /**
     * Verifies that a null port is rejected.
     */
    @Test
    void constructor_whenRepositoryIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FindUserAccountUseCase(null));
    }

    /**
     * Verifies that the account found by the port is returned.
     */
    @Test
    void execute_whenAccountExists_returnsIt() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "{noop}encoded", true, List.of());
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));

        final var result = useCase.execute(USERNAME);

        assertTrue(result.isPresent());
        assertSame(account, result.get());
        verify(userAccountRepository).findByUsername(USERNAME);
    }

    /**
     * Verifies that an empty result is returned when the port finds no account.
     */
    @Test
    void execute_whenAccountIsMissing_returnsEmpty() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertEquals(Optional.empty(), useCase.execute(USERNAME));
    }
}
