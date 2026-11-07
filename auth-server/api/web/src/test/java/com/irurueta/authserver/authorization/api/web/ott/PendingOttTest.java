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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/** Unit tests of {@link PendingOtt}. */
class PendingOttTest {

    /** Test fixture. */
    private static final PendingOtt PENDING =
            new PendingOtt("alice", "binding-1", OttKind.CODE, OttPurpose.LOGIN, OttChannel.EMAIL);

    /** A saved pending token is found in the session of the request. */
    @Test
    void of_whenTheSessionHoldsOne_findsIt() {
        final var request = new MockHttpServletRequest();
        PENDING.saveTo(request.getSession());

        assertEquals(PENDING, PendingOtt.of(request).orElseThrow());
    }

    /** A request without a session has none, and no session is created to look. */
    @Test
    void of_whenThereIsNoSession_isEmptyAndCreatesNoSession() {
        final var request = new MockHttpServletRequest();

        assertTrue(PendingOtt.of(request).isEmpty());
        assertNull(request.getSession(false));
    }

    /** A session whose attribute is not a pending token has none. */
    @Test
    void of_whenTheAttributeIsSomethingElse_isEmpty() {
        final var request = new MockHttpServletRequest();
        request.getSession().setAttribute(PendingOtt.ATTRIBUTE, "nonsense");

        assertTrue(PendingOtt.of(request).isEmpty());
    }

    /** Saving again replaces the previous pending token. */
    @Test
    void saveTo_whenOneIsAlreadyPending_replacesIt() {
        final var request = new MockHttpServletRequest();
        PENDING.saveTo(request.getSession());
        final var newer = new PendingOtt("alice", "binding-2", OttKind.LINK, OttPurpose.SECOND_FACTOR,
                OttChannel.EMAIL);
        newer.saveTo(request.getSession());

        assertEquals(newer, PendingOtt.of(request).orElseThrow());
    }

    /** Clearing forgets the pending token. */
    @Test
    void clear_whenOneIsPending_forgetsIt() {
        final var request = new MockHttpServletRequest();
        PENDING.saveTo(request.getSession());

        PendingOtt.clear(request);

        assertTrue(PendingOtt.of(request).isEmpty());
    }

    /** Clearing without a session does nothing and creates none. */
    @Test
    void clear_whenThereIsNoSession_createsNoSession() {
        final var request = new MockHttpServletRequest();

        PendingOtt.clear(request);

        assertNull(request.getSession(false));
    }

    /** The description does not carry the binding id. */
    @Test
    void toString_whenCalled_omitsTheBindingId() {
        assertFalse(PENDING.toString().contains("binding-1"));
    }
}
