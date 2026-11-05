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

package com.irurueta.authserver.authorization.api.web.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests of {@link UserAccountUserDetailsService}.
 */
@ExtendWith(MockitoExtension.class)
class UserAccountUserDetailsServiceTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Use case that looks the account up. */
    @Mock
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Service under test. */
    @InjectMocks
    private UserAccountUserDetailsService service;

    /**
     * Verifies that an enabled account is mapped to enabled user details.
     */
    @Test
    void loadUserByUsername_whenAccountIsEnabled_returnsEnabledUser() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(
                new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER))));

        final var user = service.loadUserByUsername(USERNAME);

        assertEquals(USERNAME, user.getUsername());
        assertEquals(ENCODED_PASSWORD, user.getPassword());
        assertTrue(user.isEnabled());
        assertEquals(List.of(ROLE_USER), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    /**
     * Verifies that a disabled account is mapped to disabled user details.
     */
    @Test
    void loadUserByUsername_whenAccountIsDisabled_returnsDisabledUser() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(
                new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, false, List.of())));

        final var user = service.loadUserByUsername(USERNAME);

        assertFalse(user.isEnabled());
        assertTrue(user.getAuthorities().isEmpty());
    }

    /**
     * Verifies that a missing account is reported with Spring Security's exception.
     */
    @Test
    void loadUserByUsername_whenAccountIsMissing_throwsUsernameNotFoundException() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());

        final var error = assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername(USERNAME));

        assertTrue(error.getMessage().contains(USERNAME));
    }
}
