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
import com.irurueta.authserver.authorization.application.totp.VerifyRecoveryCodeUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyTotpUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
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

    /** Verifies TOTP codes. */
    @Mock
    private VerifyTotpUseCase verifyTotpUseCase;

    /** Verifies recovery codes. */
    @Mock
    private VerifyRecoveryCodeUseCase verifyRecoveryCodeUseCase;

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
     * Verifies that a valid TOTP code grants the factor.
     */
    @Test
    void authenticate_whenTotpCodeIsValid_grantsTheTotpFactor() {
        final var granted = UsernamePasswordAuthenticationToken.authenticated(USERNAME, "secret", List.of());
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(verifyTotpUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(true);
        when(factorGrantor.grant(primary, TotpFactor.AUTHORITY)).thenReturn(granted);

        final var result = provider.authenticate(new TotpAuthenticationToken(primary, CODE, false));

        assertSame(granted, result);
        verifyNoInteractions(verifyRecoveryCodeUseCase);
    }

    /**
     * Verifies that a recovery code is verified by the recovery use case.
     */
    @Test
    void authenticate_whenRecoveryCodeIsValid_grantsTheTotpFactor() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(verifyRecoveryCodeUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(true);
        when(factorGrantor.grant(primary, TotpFactor.AUTHORITY)).thenReturn(primary);

        final var result = provider.authenticate(new TotpAuthenticationToken(primary, CODE, true));

        assertSame(primary, result);
        verifyNoInteractions(verifyTotpUseCase);
    }

    /**
     * Verifies that a wrong code is rejected.
     */
    @Test
    void authenticate_whenCodeIsWrong_throwsBadCredentialsException() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(verifyTotpUseCase.execute(USER_ID, USERNAME, CODE)).thenReturn(false);
        final var request = new TotpAuthenticationToken(primary, CODE, false);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(request));
        verifyNoInteractions(factorGrantor);
    }

    /**
     * Verifies that a locked second factor is reported as a locked account, even when the code is correct.
     */
    @Test
    void authenticate_whenSecondFactorIsLocked_throwsLockedException() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(USER_ID);
        when(verifyTotpUseCase.execute(USER_ID, USERNAME, CODE)).thenThrow(new SecondFactorLockedException("locked"));
        final var request = new TotpAuthenticationToken(primary, CODE, false);

        assertThrows(LockedException.class, () -> provider.authenticate(request));
        verify(userResolver).userIdOf(USERNAME);
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
