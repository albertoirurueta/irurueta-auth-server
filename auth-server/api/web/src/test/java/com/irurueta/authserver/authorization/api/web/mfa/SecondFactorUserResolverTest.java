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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests of {@link SecondFactorUserResolver}.
 */
@ExtendWith(MockitoExtension.class)
class SecondFactorUserResolverTest {

    /** Use case that looks the account up. */
    @Mock
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Resolver under test. */
    @InjectMocks
    private SecondFactorUserResolver resolver;

    /**
     * Verifies that the identifier of an existing account is returned.
     */
    @Test
    void userIdOf_whenAccountExists_returnsItsId() {
        final var id = UUID.randomUUID();
        when(findUserAccountUseCase.execute("alice"))
                .thenReturn(Optional.of(new UserAccount(id, "alice", "hash", true, List.of())));

        assertEquals(id, resolver.userIdOf("alice"));
    }

    /**
     * Verifies that an unknown account is reported.
     */
    @Test
    void userIdOf_whenAccountIsMissing_throwsUsernameNotFoundException() {
        when(findUserAccountUseCase.execute("bob")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> resolver.userIdOf("bob"));
    }
}
