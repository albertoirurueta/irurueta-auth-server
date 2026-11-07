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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.totp.TotpSecondFactorFragment;
import com.irurueta.authserver.authorization.application.passkeys.HasConfirmedPasskeyUseCase;
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
 * Unit tests of {@link PasskeySecondFactorFragment}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeySecondFactorFragmentTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Tells whether the user has a passkey. */
    @Mock
    private HasConfirmedPasskeyUseCase hasConfirmedPasskeyUseCase;

    /** Fragment under test. */
    @InjectMocks
    private PasskeySecondFactorFragment fragment;

    /** The signed-in user. */
    private final UsernamePasswordAuthenticationToken user =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, List.of());

    /**
     * Verifies that the fragment is the form of the passkeys second-factor template.
     */
    @Test
    void reference_whenAsked_pointsAtTheFormFragmentOfTheSecondFactorTemplate() {
        assertEquals("passkeys-second-factor :: form", fragment.reference());
    }

    /**
     * Verifies that the passkey action comes after the TOTP forms.
     */
    @Test
    void order_whenAsked_isAfterTheTotpForms() {
        assertEquals(PasskeySecondFactorFragment.ORDER, fragment.order());
        assertTrue(fragment.order() > TotpSecondFactorFragment.ORDER);
    }

    /**
     * Verifies that a user with a passkey is offered it.
     */
    @Test
    void modelAttributes_whenUserHasAPasskey_makesItAvailable() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(hasConfirmedPasskeyUseCase.execute(userId)).thenReturn(true);

        assertEquals(Map.of(PasskeySecondFactorFragment.AVAILABLE_ATTRIBUTE, true), fragment.modelAttributes(user));
    }

    /**
     * Verifies that a user without a passkey is not offered one.
     */
    @Test
    void modelAttributes_whenUserHasNoPasskey_makesItUnavailable() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(hasConfirmedPasskeyUseCase.execute(userId)).thenReturn(false);

        assertEquals(Map.of(PasskeySecondFactorFragment.AVAILABLE_ATTRIBUTE, false), fragment.modelAttributes(user));
    }

    /**
     * Verifies that nothing is looked up when nobody is signed in.
     */
    @Test
    void modelAttributes_whenNobodyIsSignedIn_isEmpty() {
        final var anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertTrue(fragment.modelAttributes(anonymous).isEmpty());
        assertTrue(fragment.modelAttributes(null).isEmpty());
        verifyNoInteractions(userResolver, hasConfirmedPasskeyUseCase);
    }
}
