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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Unit tests of {@link TotpAuthenticationProvider}.
 */
@ExtendWith(MockitoExtension.class)
class TotpAuthenticationProviderTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** The code. */
    private static final String CODE = "123456";

    /** Identifier of the account. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Sends the codes to the use case of their kind. */
    @Mock
    private TotpCodeVerifier totpCodeVerifier;

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Adds the factor authority. */
    @Mock
    private FactorGrantor factorGrantor;

    /** Provider under test. */
    @InjectMocks
    private TotpAuthenticationProvider provider;

    /** The authentication the user already holds. */
    private final Authentication primary =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", List.of());

    /**
     * Verifies that an accepted code grants the factor.
     */
    @Test
    void authenticate_whenCodeIsAccepted_grantsTheTotpFactor() {
        final var granted = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", List.of());
        final var request = new TotpAuthenticationToken(primary, CODE, TotpCodeKind.TOTP);
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(totpCodeVerifier.verify(request, USER_ID, USERNAME)).thenReturn(true);
        when(factorGrantor.grant(primary, TotpFactor.AUTHORITY)).thenReturn(granted);

        assertSame(granted, provider.authenticate(request));
    }

    /**
     * Verifies that a wrong code is rejected.
     */
    @Test
    void authenticate_whenCodeIsWrong_throwsBadCredentialsException() {
        final var request = new TotpAuthenticationToken(primary, CODE, TotpCodeKind.TOTP);
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(totpCodeVerifier.verify(request, USER_ID, USERNAME)).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(factorGrantor);
    }

    /**
     * Verifies that a locked second factor is reported as a locked account, even when the code is correct.
     */
    @Test
    void authenticate_whenSecondFactorIsLocked_throwsLockedException() {
        final var request = new TotpAuthenticationToken(primary, CODE, TotpCodeKind.TOTP);
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(totpCodeVerifier.verify(request, USER_ID, USERNAME)).thenThrow(new SecondFactorLockedException("locked"));

        assertThrows(LockedException.class, () -> provider.authenticate(request));
        verify(userResolver).userIdOf(USERNAME);
    }

    /**
     * Verifies that an enrolment code with no enrolment waiting to be confirmed is a bad credential.
     */
    @Test
    void authenticate_whenNoEnrolmentIsPending_throwsBadCredentialsException() {
        final var request = new TotpAuthenticationToken(primary, CODE, TotpCodeKind.ENROLMENT);
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(totpCodeVerifier.verify(request, USER_ID, USERNAME))
                .thenThrow(new TotpNotEnrolledException("none"));

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(factorGrantor);
    }

    /**
     * Verifies that an enrolment code for an app already enabled is a bad credential.
     */
    @Test
    void authenticate_whenAppIsAlreadyEnabled_throwsBadCredentialsException() {
        final var request = new TotpAuthenticationToken(primary, CODE, TotpCodeKind.ENROLMENT);
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(totpCodeVerifier.verify(request, USER_ID, USERNAME))
                .thenThrow(new TotpAlreadyEnabledException("enabled"));

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
    }

    /**
     * Verifies which requests the provider supports.
     */
    @Test
    void supports_whenAsked_acceptsOnlyTotpRequests() {
        assertTrue(provider.supports(TotpAuthenticationToken.class));
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }
}
