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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.sms.HasVerifiedPhoneUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/** Unit tests of {@link OttSecondFactorChannels}. */
@ExtendWith(MockitoExtension.class)
class OttSecondFactorChannelsTest {

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

    /** Tells whether the user has a confirmed second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Tells whether the user has a verified phone. */
    @Mock
    private HasVerifiedPhoneUseCase hasVerifiedPhoneUseCase;

    /** Rule under test. */
    @InjectMocks
    private OttSecondFactorChannels channels;

    /**
     * A user who signed in with a password, has no confirmed second factor (multi-factor forced by an administrator)
     * and no phone may use e-mail only.
     */
    @Test
    void allowed_whenUserHasNoSecondFactorAndNoPhone_isEmailOnly() {
        stub(false, false, false, false);

        assertEquals(EnumSet.of(OttChannel.EMAIL), channels.allowed(user));
        assertTrue(channels.isAllowed(user, OttChannel.EMAIL));
        assertFalse(channels.isAllowed(user, OttChannel.SMS));
    }

    /**
     * A user with a verified phone has a confirmed second factor, so e-mail is not allowed: only SMS. A mailbox, which
     * also resets the password, never stands in for the stronger factor.
     */
    @Test
    void allowed_whenUserHasAVerifiedPhone_isSmsOnly() {
        stub(false, false, true, true);

        assertEquals(EnumSet.of(OttChannel.SMS), channels.allowed(user));
    }

    /** A user with another confirmed second factor (an authenticator app, a passkey) and no phone may use neither. */
    @Test
    void allowed_whenUserHasAnotherSecondFactorAndNoPhone_isEmpty() {
        stub(false, false, true, false);

        assertTrue(channels.allowed(user).isEmpty());
        assertFalse(channels.isAllowed(user, OttChannel.EMAIL));
    }

    /** A user who signed in by e-mail is never allowed e-mail again, and the second factors are not even asked. */
    @Test
    void allowed_whenEmailSignedTheUserIn_isNotEmail() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(true);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(false);
        when(hasVerifiedPhoneUseCase.execute(userId)).thenReturn(true);

        assertEquals(EnumSet.of(OttChannel.SMS), channels.allowed(user));
        verifyNoInteractions(hasConfirmedSecondFactorUseCase);
    }

    /** A user who signed in by SMS is never allowed SMS again, and the phone is not even looked up. */
    @Test
    void allowed_whenSmsSignedTheUserIn_isNotSms() {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(false);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(true);
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);

        assertTrue(channels.allowed(user).isEmpty());
        verifyNoInteractions(hasVerifiedPhoneUseCase);
    }

    /**
     * Stubs the session and the account.
     *
     * @param emailSignedIn  whether e-mail signed the user in.
     * @param smsSignedIn    whether SMS signed the user in.
     * @param hasSecondFactor whether the user has a confirmed second factor.
     * @param hasPhone       whether the user has a verified phone.
     */
    private void stub(final boolean emailSignedIn, final boolean smsSignedIn, final boolean hasSecondFactor,
            final boolean hasPhone) {
        when(userResolver.userIdOf(USERNAME)).thenReturn(userId);
        when(primaryFactorSession.signedInThrough(user, OttChannel.EMAIL)).thenReturn(emailSignedIn);
        when(primaryFactorSession.signedInThrough(user, OttChannel.SMS)).thenReturn(smsSignedIn);
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(hasSecondFactor);
        when(hasVerifiedPhoneUseCase.execute(userId)).thenReturn(hasPhone);
    }
}
