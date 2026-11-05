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

package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link BeanConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class BeanConfigurationTest {

    /** Username used by the test. */
    private static final String USERNAME = "alice";

    /** Port that provides the user accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

    /** Configuration under test. */
    private final BeanConfiguration configuration = new BeanConfiguration();

    /**
     * Verifies that the use case is wired to the given port.
     */
    @Test
    void findUserAccountUseCase_whenCalled_wiresTheUseCaseToThePort() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "{noop}encoded", true, List.of());
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.of(account));

        final var useCase = configuration.findUserAccountUseCase(userAccountRepository);

        assertSame(account, useCase.execute(USERNAME).orElseThrow());
    }
}
