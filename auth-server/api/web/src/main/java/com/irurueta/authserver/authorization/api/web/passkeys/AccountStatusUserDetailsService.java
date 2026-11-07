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

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * A {@link UserDetailsService} that refuses a disabled, locked or expired account.
 *
 * <p>Spring's WebAuthn provider loads the user a verified passkey belongs to and trusts it: unlike the password
 * provider (see {@code PasswordAuthenticationConfiguration}) it never checks the status of the account. Handing it
 * this decorator makes the passkey sign-in refuse the accounts the password sign-in refuses. The provider turns any
 * exception into a bad-credentials failure, so the page shows the generic message.
 */
@RequiredArgsConstructor
public class AccountStatusUserDetailsService implements UserDetailsService {

    /** Service that loads the account. */
    private final UserDetailsService delegate;

    /** Checker of the status of the account. */
    private final UserDetailsChecker checker = new AccountStatusUserDetailsChecker();

    /**
     * Loads an account that may sign in.
     *
     * @param username name of the user.
     * @return the account.
     * @throws UsernameNotFoundException                                if there is no such account.
     * @throws org.springframework.security.authentication.AccountStatusException if the account is disabled, locked
     *                                                                  or expired.
     */
    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final var user = delegate.loadUserByUsername(username);
        checker.check(user);
        return user;
    }
}
