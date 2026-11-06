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

package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Unit tests of {@link LoginErrorMessages}.
 */
class LoginErrorMessagesTest {

    /** Mapper under test. */
    private final LoginErrorMessages messages = new LoginErrorMessages();

    /**
     * Verifies that bad credentials show the generic message.
     */
    @Test
    void keyOf_whenCredentialsAreBad_isGeneric() {
        assertEquals(LoginErrorMessages.GENERIC, messages.keyOf(new BadCredentialsException("x")));
    }

    /**
     * Verifies that an unknown user shows the same message as bad credentials, so the responses are identical.
     */
    @Test
    void keyOf_whenUserIsUnknown_isTheSameAsBadCredentials() {
        assertEquals(messages.keyOf(new BadCredentialsException("x")),
                messages.keyOf(new UsernameNotFoundException("unknown")));
    }

    /**
     * Verifies that a locked account shows its own message.
     */
    @Test
    void keyOf_whenAccountIsLocked_isLocked() {
        assertEquals(LoginErrorMessages.LOCKED, messages.keyOf(new LockedException("x")));
    }

    /**
     * Verifies that an expired account shows its own message.
     */
    @Test
    void keyOf_whenAccountIsExpired_isAccountExpired() {
        assertEquals(LoginErrorMessages.ACCOUNT_EXPIRED, messages.keyOf(new AccountExpiredException("x")));
    }

    /**
     * Verifies that expired credentials show their own message.
     */
    @Test
    void keyOf_whenCredentialsAreExpired_isCredentialsExpired() {
        assertEquals(LoginErrorMessages.CREDENTIALS_EXPIRED, messages.keyOf(new CredentialsExpiredException("x")));
    }

    /**
     * Verifies that a disabled account shows its own message.
     */
    @Test
    void keyOf_whenAccountIsDisabled_isDisabled() {
        assertEquals(LoginErrorMessages.DISABLED, messages.keyOf(new DisabledException("x")));
    }

    /**
     * Verifies that an unexpected failure never leaks its cause.
     */
    @Test
    void keyOf_whenFailureIsUnexpected_isGeneric() {
        assertEquals(LoginErrorMessages.GENERIC, messages.keyOf(new InternalAuthenticationServiceException("x")));
    }

    /**
     * Verifies that a missing exception shows the generic message.
     */
    @Test
    void keyOf_whenThereIsNoException_isGeneric() {
        assertEquals(LoginErrorMessages.GENERIC, messages.keyOf(null));
    }
}
