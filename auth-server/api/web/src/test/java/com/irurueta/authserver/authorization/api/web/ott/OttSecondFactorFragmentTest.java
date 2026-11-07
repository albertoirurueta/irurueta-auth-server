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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.passkeys.PasskeySecondFactorFragment;
import com.irurueta.authserver.authorization.application.sms.HasVerifiedPhoneUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
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

/** Unit tests of {@link OttSecondFactorFragment}. */
@ExtendWith(MockitoExtension.class)
class OttSecondFactorFragmentTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** The signed-in user. */
    private final UsernamePasswordAuthenticationToken user =
            UsernamePasswordAuthenticationToken.authenticated(USERNAME, null, List.of());

    /** Rules about the session. */
    @Mock
    private PrimaryFactorSession primaryFactorSession;

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Tells whether the user has a verified phone. */
    @Mock
    private HasVerifiedPhoneUseCase hasVerifiedPhoneUseCase;

    /** Fragment under test. */
    @InjectMocks
    private OttSecondFactorFragment fragment;

    /** The fragment is the form of the ott-second-factor template. */
    @Test
    void reference_whenAsked_pointsAtTheFormFragmentOfTheTemplate() {
        assertEquals("ott-second-factor :: form", fragment.reference());
    }

    /** The action comes after the passkey one. */
    @Test
    void order_whenAsked_isAfterThePasskeyAction() {
        assertEquals(OttSecondFactorFragment.ORDER, fragment.order());
        assertTrue(fragment.order() > PasskeySecondFactorFragment.ORDER);
    }

    /** A user who signed in with a password and has a verified phone is offered both channels. */
    @Test
    void modelAttributes_whenNoChannelSignedTheUserInAndThereIsAPhone_offersBoth() {
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(false);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(false);
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(hasVerifiedPhoneUseCase.execute(userId)).thenReturn(true);

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, true,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, true), fragment.modelAttributes(user));
    }

    /** A user without a verified phone is offered e-mail only. */
    @Test
    void modelAttributes_whenThereIsNoPhone_offersEmailOnly() {
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(false);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(false);
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(hasVerifiedPhoneUseCase.execute(userId)).thenReturn(false);

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, true,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, false), fragment.modelAttributes(user));
    }

    /** A user who signed in by e-mail is not offered e-mail again. */
    @Test
    void modelAttributes_whenEmailSignedTheUserIn_doesNotOfferEmail() {
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(true);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(false);
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(hasVerifiedPhoneUseCase.execute(userId)).thenReturn(true);

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, false,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, true), fragment.modelAttributes(user));
    }

    /** A user who signed in by SMS is not offered SMS again, and the phone is not even looked up. */
    @Test
    void modelAttributes_whenSmsSignedTheUserIn_doesNotOfferSms() {
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(false);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(true);

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, true,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, false), fragment.modelAttributes(user));
        verifyNoInteractions(hasVerifiedPhoneUseCase, userResolver);
    }

    /** Nothing is looked up when nobody is signed in. */
    @Test
    void modelAttributes_whenNobodyIsSignedIn_isEmpty() {
        final var anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertTrue(fragment.modelAttributes(anonymous).isEmpty());
        assertTrue(fragment.modelAttributes(null).isEmpty());
        verifyNoInteractions(primaryFactorSession, userResolver, hasVerifiedPhoneUseCase);
    }
}
