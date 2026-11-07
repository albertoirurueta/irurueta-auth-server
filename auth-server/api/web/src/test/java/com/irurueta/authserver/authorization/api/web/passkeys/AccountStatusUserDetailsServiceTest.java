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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests of {@link AccountStatusUserDetailsService}.
 */
@ExtendWith(MockitoExtension.class)
class AccountStatusUserDetailsServiceTest {

    /** Name of the user. */
    private static final String USERNAME = "alice";

    /** Service that loads the account. */
    @Mock
    private UserDetailsService delegate;

    /** Service under test. */
    @InjectMocks
    private AccountStatusUserDetailsService service;

    /**
     * Verifies that an enabled account is handed over unchanged.
     */
    @Test
    void loadUserByUsername_whenAccountIsEnabled_returnsIt() {
        final var user = User.withUsername(USERNAME).password("x").build();
        when(delegate.loadUserByUsername(USERNAME)).thenReturn(user);

        assertSame(user, service.loadUserByUsername(USERNAME));
    }

    /**
     * Verifies that a disabled account is refused.
     */
    @Test
    void loadUserByUsername_whenAccountIsDisabled_throwsDisabledException() {
        when(delegate.loadUserByUsername(USERNAME))
                .thenReturn(User.withUsername(USERNAME).password("x").disabled(true).build());

        assertThrows(DisabledException.class, () -> service.loadUserByUsername(USERNAME));
    }

    /**
     * Verifies that a locked account is refused.
     */
    @Test
    void loadUserByUsername_whenAccountIsLocked_throwsLockedException() {
        when(delegate.loadUserByUsername(USERNAME))
                .thenReturn(User.withUsername(USERNAME).password("x").accountLocked(true).build());

        assertThrows(LockedException.class, () -> service.loadUserByUsername(USERNAME));
    }

    /**
     * Verifies that an unknown user is still reported as such.
     */
    @Test
    void loadUserByUsername_whenAccountIsMissing_throwsUsernameNotFoundException() {
        when(delegate.loadUserByUsername(USERNAME)).thenThrow(new UsernameNotFoundException(USERNAME));

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername(USERNAME));
    }
}
