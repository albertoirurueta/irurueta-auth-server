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

import static org.mockito.Mockito.verify;

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

    /** Outdated encoded password used by the tests. */
    private static final String OLD = "{bcrypt}old";

    /** Current encoded password used by the tests. */
    private static final String NEW = "{argon2}new";

    /** Port that stores the accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Use case under test. */
    @InjectMocks
    private UpgradePasswordHashUseCase useCase;

    /**
     * Verifies that an already encoded hash is stored as given.
     */
    @Test
    void replaceHash_whenCalled_storesGivenHash() {
        final var account = account();

        useCase.replaceHash(account, NEW);

        verify(userAccountRepository).updatePassword(account.id(), NEW);
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
