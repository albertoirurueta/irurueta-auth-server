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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;

/** Unit tests of {@link OttAuthenticationConverter}. */
class OttAuthenticationConverterTest {

    /** Converter under test. */
    private final OttAuthenticationConverter converter = new OttAuthenticationConverter();

    /** A post without a token is not converted. */
    @Test
    void convert_whenNoTokenIsPosted_returnsNull() {
        final var request = new MockHttpServletRequest();
        request.setParameter("token", "  ");

        assertNull(converter.convert(new MockHttpServletRequest()));
        assertNull(converter.convert(request));
    }

    /** A UUID is the token of a magic link. */
    @Test
    void convert_whenAUuidIsPosted_isALinkToken() {
        final var request = new MockHttpServletRequest();
        request.setParameter("token", " 7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c ");

        final var converted = assertInstanceOf(OneTimeTokenAuthenticationToken.class, converter.convert(request));

        assertEquals("7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c", converted.getTokenValue());
    }

    /** Digits are a code, tied to what the session requested. */
    @Test
    void convert_whenDigitsArePosted_isACodeTiedToThePendingToken() {
        final var request = new MockHttpServletRequest();
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.LOGIN, OttChannel.EMAIL)
                .saveTo(request.getSession());
        request.setParameter("token", "123456");

        final var converted = assertInstanceOf(OttCodeAuthenticationToken.class, converter.convert(request));

        assertEquals("alice", converted.getPrincipal());
        assertEquals("123456", converted.getCredentials());
        assertEquals("binding", converted.bindingId());
    }

    /** A code from a browser that asked for none is still converted, with nothing to match. */
    @Test
    void convert_whenACodeIsPostedWithoutPendingToken_isACodeWithEmptyBinding() {
        final var request = new MockHttpServletRequest();
        request.setParameter("token", "123456");

        final var converted = assertInstanceOf(OttCodeAuthenticationToken.class, converter.convert(request));

        assertEquals("", converted.getPrincipal());
        assertEquals("", converted.bindingId());
    }
}
