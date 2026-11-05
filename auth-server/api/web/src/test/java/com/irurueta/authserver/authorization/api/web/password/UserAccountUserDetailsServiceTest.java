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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.application.password.UpgradePasswordHashUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.User;
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

    /** Upgraded encoded password used by the tests; not a real credential. */
    private static final String NEW_ENCODED_PASSWORD = "{argon2}upgraded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Use case that looks the account up. */
    @Mock
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Use case that stores the upgraded hash. */
    @Mock
    private UpgradePasswordHashUseCase upgradePasswordHashUseCase;

    /** Maps an account onto user details. */
    @Mock
    private UserDetailsMapper userDetailsMapper;

    /** Service under test. */
    @InjectMocks
    private UserAccountUserDetailsService service;

    /**
     * Verifies that a found account is mapped through the mapper with its stored password.
     */
    @Test
    void loadUserByUsername_whenAccountExists_returnsMappedUser() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));
        final var details = User.withUsername(USERNAME).password(ENCODED_PASSWORD).authorities(ROLE_USER).build();
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account));
        when(userDetailsMapper.toUserDetails(account, ENCODED_PASSWORD)).thenReturn(details);

        final var user = service.loadUserByUsername(USERNAME);

        assertSame(details, user);
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

    /**
     * Verifies that the upgraded hash is stored and carried by the returned details.
     */
    @Test
    void updatePassword_whenAccountExists_storesHashAndReturnsUpdatedUser() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account));
        final var current = User.withUsername(USERNAME).password(ENCODED_PASSWORD).authorities(ROLE_USER).build();

        final var details = User.withUsername(USERNAME).password(NEW_ENCODED_PASSWORD).authorities(ROLE_USER)
                .build();
        when(userDetailsMapper.toUserDetails(account, NEW_ENCODED_PASSWORD)).thenReturn(details);

        final var updated = service.updatePassword(current, NEW_ENCODED_PASSWORD);

        verify(upgradePasswordHashUseCase).replaceHash(account, NEW_ENCODED_PASSWORD);
        assertSame(details, updated);
    }

    /**
     * Verifies that a missing account is reported and nothing is stored.
     */
    @Test
    void updatePassword_whenAccountIsMissing_throwsUsernameNotFoundException() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());
        final var current = User.withUsername(USERNAME).password(ENCODED_PASSWORD).authorities(ROLE_USER).build();

        assertThrows(UsernameNotFoundException.class, () -> service.updatePassword(current, NEW_ENCODED_PASSWORD));

        verify(upgradePasswordHashUseCase, never()).replaceHash(any(), any());
    }
}
