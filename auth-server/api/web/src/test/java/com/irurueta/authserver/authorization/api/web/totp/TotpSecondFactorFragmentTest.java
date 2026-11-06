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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.totp.CountRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.application.totp.EnrollTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.IsTotpEnabledUseCase;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Unit tests of {@link TotpSecondFactorFragment}.
 */
@ExtendWith(MockitoExtension.class)
class TotpSecondFactorFragmentTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** The enrolment URI returned by the mocked use case. */
    private static final String OTPAUTH_URI = "otpauth://totp/Issuer:alice?secret=ABC";

    /** The QR code returned by the mocked renderer. */
    private static final String QR_CODE = "data:image/png;base64,AA";

    /** Recovery codes left of a user with plenty of them. */
    private static final int MANY_CODES = 8;

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Tells whether the user has a confirmed authenticator app. */
    @Mock
    private IsTotpEnabledUseCase isTotpEnabledUseCase;

    /** Starts an enrolment. */
    @Mock
    private EnrollTotpUseCase enrollTotpUseCase;

    /** Counts the unused recovery codes. */
    @Mock
    private CountRecoveryCodesUseCase countRecoveryCodesUseCase;

    /** Renders the QR code. */
    @Mock
    private QrCodeRenderer qrCodeRenderer;

    /** Fragment under test. */
    @InjectMocks
    private TotpSecondFactorFragment fragment;

    /** The signed-in user. */
    private final UsernamePasswordAuthenticationToken user =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, List.of());

    /**
     * Verifies that the fragment is the form of the totp template.
     */
    @Test
    void reference_whenAsked_pointsAtTheFormFragmentOfTheTotpTemplate() {
        assertEquals("totp :: form", fragment.reference());
    }

    /**
     * Verifies the position of the fragment.
     */
    @Test
    void order_whenAsked_isTheConstant() {
        assertEquals(TotpSecondFactorFragment.ORDER, fragment.order());
    }

    /**
     * Verifies that a user without a confirmed app gets a new enrolment, as a URI and a QR code.
     */
    @Test
    void modelAttributes_whenUserHasNoApp_startsAnEnrolment() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(isTotpEnabledUseCase.execute(userId)).thenReturn(false);
        when(enrollTotpUseCase.execute(userId, USERNAME)).thenReturn(OTPAUTH_URI);
        when(qrCodeRenderer.render(OTPAUTH_URI)).thenReturn(QR_CODE);

        assertEquals(Map.of(TotpSecondFactorFragment.ENROLMENT_ATTRIBUTE, true,
                TotpSecondFactorFragment.OTPAUTH_URI_ATTRIBUTE, OTPAUTH_URI,
                TotpSecondFactorFragment.QR_CODE_ATTRIBUTE, QR_CODE), fragment.modelAttributes(user));
        verifyNoInteractions(countRecoveryCodesUseCase);
    }

    /**
     * Verifies that a user with an app and few recovery codes is warned, with the count.
     */
    @Test
    void modelAttributes_whenFewRecoveryCodesAreLeft_flagsTheWarning() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(isTotpEnabledUseCase.execute(userId)).thenReturn(true);
        when(countRecoveryCodesUseCase.execute(userId)).thenReturn(CountRecoveryCodesUseCase.LOW_THRESHOLD);

        assertEquals(Map.of(TotpSecondFactorFragment.ENROLMENT_ATTRIBUTE, false,
                TotpSecondFactorFragment.CODES_LEFT_ATTRIBUTE, CountRecoveryCodesUseCase.LOW_THRESHOLD,
                TotpSecondFactorFragment.CODES_LOW_ATTRIBUTE, true), fragment.modelAttributes(user));
        verifyNoInteractions(enrollTotpUseCase);
    }

    /**
     * Verifies that a user with plenty of recovery codes is not warned.
     */
    @Test
    void modelAttributes_whenManyRecoveryCodesAreLeft_doesNotFlagTheWarning() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(isTotpEnabledUseCase.execute(userId)).thenReturn(true);
        when(countRecoveryCodesUseCase.execute(userId)).thenReturn(MANY_CODES);

        assertEquals(Boolean.FALSE,
                fragment.modelAttributes(user).get(TotpSecondFactorFragment.CODES_LOW_ATTRIBUTE));
    }

    /**
     * Verifies that nothing is contributed when nobody is signed in.
     */
    @Test
    void modelAttributes_whenNobodyIsSignedIn_returnsNothing() {
        assertTrue(fragment.modelAttributes(null).isEmpty());
        assertTrue(fragment.modelAttributes(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))).isEmpty());
        verifyNoInteractions(userResolver);
    }
}
