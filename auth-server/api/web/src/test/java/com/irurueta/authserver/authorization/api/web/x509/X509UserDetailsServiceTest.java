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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.x509.ResolveCertificateLoginUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Unit tests of {@link X509UserDetailsService}.
 */
@ExtendWith(MockitoExtension.class)
class X509UserDetailsServiceTest {

    /** A fingerprint. */
    private static final String FINGERPRINT = "ab".repeat(32);

    /** Name of the account. */
    private static final String USERNAME = "alice";

    /** Finds the account of a fingerprint. */
    @Mock
    private ResolveCertificateLoginUseCase resolveCertificateLoginUseCase;

    /** Loads the account. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Service under test. */
    @InjectMocks
    private X509UserDetailsService service;

    /**
     * Verifies that the account bound to the certificate is loaded.
     */
    @Test
    void loadUserDetails_whenCertificateIsBound_loadsTheAccount() {
        final var user = User.withUsername(USERNAME).password("x").authorities("ROLE_USER").build();
        when(resolveCertificateLoginUseCase.execute(FINGERPRINT)).thenReturn(Optional.of(account()));
        when(userDetailsService.loadUserByUsername(USERNAME)).thenReturn(user);

        assertSame(user, service.loadUserDetails(token()));
    }

    /**
     * Verifies that a certificate that is bound to nobody is refused, and that no account is loaded.
     */
    @Test
    void loadUserDetails_whenCertificateIsNotBound_throwsUsernameNotFound() {
        when(resolveCertificateLoginUseCase.execute(FINGERPRINT)).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserDetails(token()));

        verifyNoInteractions(userDetailsService);
    }

    /**
     * Verifies that the refusal of the user service for a disabled, locked or expired account propagates.
     */
    @Test
    void loadUserDetails_whenTheAccountCannotSignIn_propagatesTheRefusal() {
        when(resolveCertificateLoginUseCase.execute(FINGERPRINT)).thenReturn(Optional.of(account()));
        when(userDetailsService.loadUserByUsername(USERNAME)).thenThrow(new DisabledException("disabled"));

        assertThrows(DisabledException.class, () -> service.loadUserDetails(token()));
    }

    /**
     * Builds the token the framework hands to the service.
     *
     * @return the token.
     */
    private static PreAuthenticatedAuthenticationToken token() {
        return new PreAuthenticatedAuthenticationToken(FINGERPRINT, null);
    }

    /**
     * Builds the account.
     *
     * @return the account.
     */
    private static UserAccount account() {
        return new UserAccount(UUID.randomUUID(), USERNAME, "encoded", true, List.of("ROLE_USER"),
                "alice@example.com", true, "acme");
    }
}
