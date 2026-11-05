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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UpgradePasswordHashUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class UpgradePasswordHashUseCaseTest {

    /** Clear-text password used by the tests; not a real credential. */
    private static final String RAW = "raw-password";

    /** Outdated encoded password used by the tests. */
    private static final String OLD = "{bcrypt}old";

    /** Current encoded password used by the tests. */
    private static final String NEW = "{argon2}new";

    /** Port that hashes passwords. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private UpgradePasswordHashUseCase useCase;

    /**
     * Verifies that an outdated hash is replaced.
     */
    @Test
    void execute_whenEncodingIsOutdated_storesNewHash() {
        final var account = account();
        when(passwordHasher.upgradeEncoding(OLD)).thenReturn(true);
        when(passwordHasher.encode(RAW)).thenReturn(NEW);

        assertTrue(useCase.execute(account, RAW));

        verify(userAccountRepository).updatePassword(account.id(), NEW);
    }

    /**
     * Verifies that a current hash is left alone.
     */
    @Test
    void execute_whenEncodingIsCurrent_doesNothing() {
        when(passwordHasher.upgradeEncoding(OLD)).thenReturn(false);

        assertFalse(useCase.execute(account(), RAW));

        verifyNoInteractions(userAccountRepository);
    }

    /**
     * Verifies that an already encoded hash is stored as given, without re-encoding it.
     */
    @Test
    void replaceHash_whenCalled_storesGivenHashWithoutEncoding() {
        final var account = account();

        useCase.replaceHash(account, NEW);

        verify(userAccountRepository).updatePassword(account.id(), NEW);
        verifyNoInteractions(passwordHasher);
    }

    /**
     * Creates an account with the outdated hash.
     *
     * @return the account.
     */
    private static UserAccount account() {
        return new UserAccount(UUID.randomUUID(), "alice", OLD, true, List.of());
    }
}
