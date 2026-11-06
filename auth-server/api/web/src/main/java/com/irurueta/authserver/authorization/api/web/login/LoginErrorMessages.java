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

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * Maps the exception of a failed sign-in, which Spring Security keeps in the
 * {@code SPRING_SECURITY_LAST_EXCEPTION} session attribute, to the key of the message the login page shows.
 *
 * <p>An unknown user and a wrong password (a
 * {@link org.springframework.security.authentication.BadCredentialsException} or a
 * {@link org.springframework.security.core.userdetails.UsernameNotFoundException}) deliberately share
 * the generic key, so the two responses are identical and the page never reveals whether an account exists. The
 * account status messages (locked, disabled, expired) cannot reveal it either: the authentication provider of the
 * {@code password} feature ({@code PasswordAuthenticationConfiguration}) only checks the status after a correct
 * password, so a wrong password for a disabled account is reported as bad credentials too.
 */
@Component
public class LoginErrorMessages {

    /** Key of the message shown for bad credentials, an unknown user and any unexpected failure. */
    public static final String GENERIC = "login.error.generic";

    /** Key of the message shown for a locked account. */
    public static final String LOCKED = "login.error.locked";

    /** Key of the message shown for an expired account. */
    public static final String ACCOUNT_EXPIRED = "login.error.accountExpired";

    /** Key of the message shown for expired credentials. */
    public static final String CREDENTIALS_EXPIRED = "login.error.credentialsExpired";

    /** Key of the message shown for a disabled account. */
    public static final String DISABLED = "login.error.disabled";

    /**
     * Gets the key of the message that describes a failed sign-in.
     *
     * @param exception the exception of the failed sign-in; {@code null} when the session holds none.
     * @return the message key; the generic one for bad credentials, an unknown user and anything unexpected.
     */
    public String keyOf(final AuthenticationException exception) {
        return switch (exception) {
            case LockedException locked -> LOCKED;
            case AccountExpiredException expired -> ACCOUNT_EXPIRED;
            case CredentialsExpiredException expired -> CREDENTIALS_EXPIRED;
            case DisabledException disabled -> DISABLED;
            case null, default -> GENERIC;
        };
    }
}
