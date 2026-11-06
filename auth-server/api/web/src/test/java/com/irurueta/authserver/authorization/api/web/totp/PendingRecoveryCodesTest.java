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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Unit tests of {@link PendingRecoveryCodes}.
 */
class PendingRecoveryCodesTest {

    /** Subject under test. */
    private final PendingRecoveryCodes pending = new PendingRecoveryCodes();

    /** The request of the session. */
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    /**
     * Verifies that saved codes are pending, and taken out of the session exactly once.
     */
    @Test
    void take_whenCodesWereSaved_returnsThemOnce() {
        pending.save(request, List.of("AAAAAAAAAA", "BBBBBBBBBB"));

        assertTrue(pending.isPending(request));
        assertEquals(List.of("AAAAAAAAAA", "BBBBBBBBBB"), pending.take(request));
        assertFalse(pending.isPending(request));
        assertTrue(pending.take(request).isEmpty());
    }

    /**
     * Verifies that a request without a session has nothing pending and creates no session.
     */
    @Test
    void take_whenThereIsNoSession_returnsNothing() {
        assertFalse(pending.isPending(request));
        assertTrue(pending.take(request).isEmpty());
        assertNull(request.getSession(false));
    }

    /**
     * Verifies that an attribute of an unexpected type is dropped.
     */
    @Test
    void take_whenTheAttributeIsNotAList_returnsNothing() {
        request.getSession(true).setAttribute(PendingRecoveryCodes.ATTRIBUTE, "unexpected");

        assertTrue(pending.take(request).isEmpty());
        assertNull(request.getSession(false).getAttribute(PendingRecoveryCodes.ATTRIBUTE));
    }
}
