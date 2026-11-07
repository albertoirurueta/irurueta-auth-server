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

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** Unit tests of {@link OttGenerationParameters}. */
class OttGenerationParametersTest {

    /** A signed-in user. */
    private static final Authentication SIGNED_IN =
            UsernamePasswordAuthenticationToken.authenticated("alice", "x", AuthorityUtils.NO_AUTHORITIES);

    /** A request without fields falls back to an e-mail code for a sign-in. */
    @Test
    void from_whenNothingIsSent_isAnEmailCodeForASignIn() {
        final var parameters = OttGenerationParameters.from(new MockHttpServletRequest(), null);

        assertEquals(new OttGenerationParameters(OttChannel.EMAIL, OttKind.CODE, OttPurpose.LOGIN), parameters);
    }

    /** An e-mail magic link as a second factor of a signed-in user is read as asked. */
    @Test
    void from_whenAnEmailLinkIsAskedAsSecondFactorBySignedInUser_isReadAsAsked() {
        final var request = request("email", "LINK", "Second-Factor");

        assertEquals(new OttGenerationParameters(OttChannel.EMAIL, OttKind.LINK, OttPurpose.SECOND_FACTOR),
                OttGenerationParameters.from(request, SIGNED_IN));
    }

    /** A magic link by SMS is not possible: it is a code. */
    @Test
    void from_whenALinkIsAskedBySms_isACode() {
        final var request = request("sms", "link", null);

        assertEquals(new OttGenerationParameters(OttChannel.SMS, OttKind.CODE, OttPurpose.LOGIN),
                OttGenerationParameters.from(request, null));
    }

    /** Nobody who is not signed in can ask for a second factor. */
    @Test
    void from_whenSecondFactorIsAskedWithoutBeingSignedIn_isASignIn() {
        final var request = request(null, null, "second-factor");
        final var anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));

        assertEquals(OttPurpose.LOGIN, OttGenerationParameters.from(request, null).purpose());
        assertEquals(OttPurpose.LOGIN, OttGenerationParameters.from(request, anonymous).purpose());
    }

    /** Unknown values fall back to the defaults. */
    @Test
    void from_whenValuesAreUnknown_usesTheDefaults() {
        final var request = request("carrier-pigeon", "scroll", "whenever");

        assertEquals(new OttGenerationParameters(OttChannel.EMAIL, OttKind.CODE, OttPurpose.LOGIN),
                OttGenerationParameters.from(request, SIGNED_IN));
    }

    /** Only an authenticated, non-anonymous authentication is a signed-in user. */
    @Test
    void isSignedIn_whenAuthenticationIsMissingUnauthenticatedOrAnonymous_isFalse() {
        final var unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated("alice", "x");

        assertTrue(OttGenerationParameters.isSignedIn(SIGNED_IN));
        assertFalse(OttGenerationParameters.isSignedIn(null));
        assertFalse(OttGenerationParameters.isSignedIn(unauthenticated));
    }

    /**
     * Builds a request with the fields of a token request.
     *
     * @param channel the channel field, or {@code null}.
     * @param kind    the kind field, or {@code null}.
     * @param purpose the purpose field, or {@code null}.
     * @return the request.
     */
    private static MockHttpServletRequest request(final String channel, final String kind, final String purpose) {
        final var request = new MockHttpServletRequest();
        if (channel != null) {
            request.setParameter(OttGenerationParameters.CHANNEL_PARAMETER, channel);
        }
        if (kind != null) {
            request.setParameter(OttGenerationParameters.KIND_PARAMETER, kind);
        }
        if (purpose != null) {
            request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, purpose);
        }
        return request;
    }
}
