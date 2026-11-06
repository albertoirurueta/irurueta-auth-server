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

import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
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
 * Unit tests of {@link IsUserMfaRequiredUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class IsUserMfaRequiredUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Port that provides the user accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Port that stores the per-user multi-factor settings. */
    @Mock
    private UserMfaSettingsRepository userMfaSettingsRepository;

    /** Use case under test. */
    @InjectMocks
    private IsUserMfaRequiredUseCase useCase;

    /**
     * Verifies that an account flagged as requiring MFA is reported as such.
     */
    @Test
    void execute_whenAccountRequiresMfa_returnsTrue() {
        final var account = account();
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));
        when(userMfaSettingsRepository.isRequired(account.id())).thenReturn(true);

        assertTrue(useCase.execute(USERNAME));
    }

    /**
     * Verifies that an account that is not flagged is reported as not requiring MFA.
     */
    @Test
    void execute_whenAccountDoesNotRequireMfa_returnsFalse() {
        final var account = account();
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));
        when(userMfaSettingsRepository.isRequired(account.id())).thenReturn(false);

        assertFalse(useCase.execute(USERNAME));
    }

    /**
     * Verifies that an unknown user does not require MFA and the settings are not consulted.
     */
    @Test
    void execute_whenAccountIsMissing_returnsFalse() {
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertFalse(useCase.execute(USERNAME));
        verifyNoInteractions(userMfaSettingsRepository);
    }

    /**
     * Builds the account used by the tests.
     *
     * @return an enabled account.
     */
    private static UserAccount account() {
        return new UserAccount(UUID.randomUUID(), USERNAME, "{noop}secret", true, List.of());
    }
}
