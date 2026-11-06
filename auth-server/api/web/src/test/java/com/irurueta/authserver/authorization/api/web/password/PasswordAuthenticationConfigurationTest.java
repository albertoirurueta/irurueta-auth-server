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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests of {@link PasswordAuthenticationConfiguration}: the provider it builds, driven with the real password
 * encoder of the application and Mockito mocks of the user details services.
 */
@ExtendWith(MockitoExtension.class)
class PasswordAuthenticationConfigurationTest {

    /** Username of the test account. */
    private static final String USERNAME = "alice";

    /** Clear-text password of the test account; built at runtime, not a real credential. */
    private static final String PASSWORD = String.join("-", "correct", "test", "value");

    /** A password that is not the one of the test account. */
    private static final String WRONG_PASSWORD = String.join("-", "wrong", "test", "value");

    /** The password encoder of the application. */
    private final PasswordEncoder passwordEncoder = new PasswordConfiguration().passwordEncoder();

    /** Loads the test account. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Stores upgraded hashes. */
    @Mock
    private UserDetailsPasswordService userDetailsPasswordService;

    /** Compromised-password checker, when the test declares one. */
    @Mock
    private CompromisedPasswordChecker compromisedPasswordChecker;

    /**
     * Verifies that a wrong password for a disabled account gets the bad credentials error, as for any account, so
     * the answer does not reveal that the account exists.
     */
    @Test
    void passwordAuthenticationProvider_whenAccountIsDisabledAndPasswordIsWrong_throwsBadCredentials() {
        account(User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD)).disabled(true).build());

        assertThrows(BadCredentialsException.class, () -> provider().authenticate(login(WRONG_PASSWORD)));
    }

    /**
     * Verifies that the correct password for a disabled account gets the disabled error.
     */
    @Test
    void passwordAuthenticationProvider_whenAccountIsDisabledAndPasswordIsCorrect_throwsDisabled() {
        account(User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD)).disabled(true).build());

        assertThrows(DisabledException.class, () -> provider().authenticate(login(PASSWORD)));
    }

    /**
     * Verifies that a wrong password for a locked account gets the bad credentials error.
     */
    @Test
    void passwordAuthenticationProvider_whenAccountIsLockedAndPasswordIsWrong_throwsBadCredentials() {
        account(User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD)).accountLocked(true).build());

        assertThrows(BadCredentialsException.class, () -> provider().authenticate(login(WRONG_PASSWORD)));
    }

    /**
     * Verifies that the correct password for a locked account gets the locked error.
     */
    @Test
    void passwordAuthenticationProvider_whenAccountIsLockedAndPasswordIsCorrect_throwsLocked() {
        account(User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD)).accountLocked(true).build());

        assertThrows(LockedException.class, () -> provider().authenticate(login(PASSWORD)));
    }

    /**
     * Verifies that an unknown user is hidden behind the bad credentials error.
     */
    @Test
    void passwordAuthenticationProvider_whenUserIsUnknown_throwsBadCredentials() {
        when(userDetailsService.loadUserByUsername(USERNAME)).thenThrow(new UsernameNotFoundException(USERNAME));

        assertThrows(BadCredentialsException.class, () -> provider().authenticate(login(PASSWORD)));
    }

    /**
     * Verifies that the correct password for an enabled account with a current hash signs in without rewriting it.
     */
    @Test
    void passwordAuthenticationProvider_whenAccountIsEnabledAndPasswordIsCorrect_authenticates() {
        final var user = User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD))
                .authorities("ROLE_USER").build();
        account(user);

        final var result = provider().authenticate(login(PASSWORD));

        assertTrue(result.isAuthenticated());
        assertSame(user, result.getPrincipal());
        verify(userDetailsPasswordService, never()).updatePassword(any(), anyString());
    }

    /**
     * Verifies that a sign-in with an outdated hash hands the stronger hash to the password service.
     */
    @Test
    void passwordAuthenticationProvider_whenHashIsOutdated_storesTheUpgradedHash() {
        final var legacy = "{" + PasswordConfiguration.BCRYPT_ENCODING_ID + "}"
                + new BCryptPasswordEncoder().encode(PASSWORD);
        final var user = User.withUsername(USERNAME).password(legacy).authorities("ROLE_USER").build();
        account(user);
        when(userDetailsPasswordService.updatePassword(eq(user), anyString())).thenReturn(user);

        provider().authenticate(login(PASSWORD));

        verify(userDetailsPasswordService).updatePassword(eq(user), anyString());
    }

    /**
     * Verifies that a compromised-password checker, when one bean of that type exists, is applied to the sign-in.
     */
    @Test
    void passwordAuthenticationProvider_whenCheckerExistsAndPasswordIsCompromised_throwsCompromised() {
        account(User.withUsername(USERNAME).password(passwordEncoder.encode(PASSWORD)).authorities("ROLE_USER")
                .build());
        when(compromisedPasswordChecker.check(PASSWORD)).thenReturn(new CompromisedPasswordDecision(true));
        final var checkers = new StaticListableBeanFactory(Map.of("checker", compromisedPasswordChecker))
                .getBeanProvider(CompromisedPasswordChecker.class);

        final var provider = provider(checkers);

        assertThrows(CompromisedPasswordException.class, () -> provider.authenticate(login(PASSWORD)));
    }

    /**
     * Builds the provider with no compromised-password checker.
     *
     * @return the provider.
     */
    private DaoAuthenticationProvider provider() {
        return provider(new StaticListableBeanFactory().getBeanProvider(CompromisedPasswordChecker.class));
    }

    /**
     * Builds the provider.
     *
     * @param checkers the compromised-password checkers available.
     * @return the provider.
     */
    private DaoAuthenticationProvider provider(final ObjectProvider<CompromisedPasswordChecker> checkers) {
        return new PasswordAuthenticationConfiguration().passwordAuthenticationProvider(userDetailsService,
                userDetailsPasswordService, passwordEncoder, checkers);
    }

    /**
     * Makes the user details service return an account.
     *
     * @param user the account.
     */
    private void account(final UserDetails user) {
        when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(user);
    }

    /**
     * Builds a sign-in attempt of the test user.
     *
     * @param password the password typed.
     * @return the unauthenticated token.
     */
    private static UsernamePasswordAuthenticationToken login(final String password) {
        return UsernamePasswordAuthenticationToken.unauthenticated(USERNAME, password);
    }
}
