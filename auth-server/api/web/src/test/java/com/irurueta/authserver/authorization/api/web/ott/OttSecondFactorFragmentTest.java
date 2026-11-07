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

import com.irurueta.authserver.authorization.api.web.passkeys.PasskeySecondFactorFragment;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
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

    /** The signed-in user. */
    private final UsernamePasswordAuthenticationToken user =
            UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    /** Decides which channels may be the second factor. */
    @Mock
    private OttSecondFactorChannels secondFactorChannels;

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

    /** Both channels are offered when both are allowed. */
    @Test
    void modelAttributes_whenBothChannelsAreAllowed_offersBoth() {
        when(secondFactorChannels.allowed(user)).thenReturn(EnumSet.allOf(OttChannel.class));

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, true,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, true), fragment.modelAttributes(user));
    }

    /** Only the allowed channel is offered: SMS alone, for example, to a user with another second factor. */
    @Test
    void modelAttributes_whenOnlySmsIsAllowed_offersSmsOnly() {
        when(secondFactorChannels.allowed(user)).thenReturn(EnumSet.of(OttChannel.SMS));

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, false,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, true), fragment.modelAttributes(user));
    }

    /** Nothing is offered when no channel is allowed. */
    @Test
    void modelAttributes_whenNoChannelIsAllowed_offersNothing() {
        when(secondFactorChannels.allowed(user)).thenReturn(EnumSet.noneOf(OttChannel.class));

        assertEquals(Map.of(OttSecondFactorFragment.EMAIL_AVAILABLE_ATTRIBUTE, false,
                OttSecondFactorFragment.SMS_AVAILABLE_ATTRIBUTE, false), fragment.modelAttributes(user));
    }

    /** Nothing is looked up when nobody is signed in. */
    @Test
    void modelAttributes_whenNobodyIsSignedIn_isEmpty() {
        final var anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertTrue(fragment.modelAttributes(anonymous).isEmpty());
        assertTrue(fragment.modelAttributes(null).isEmpty());
        verifyNoInteractions(secondFactorChannels);
    }
}
