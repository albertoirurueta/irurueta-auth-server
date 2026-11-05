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

package com.irurueta.authserver.bff.domain.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SessionUser}.
 */
class SessionUserTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "demo-user";

    /** Another subject. */
    private static final String OTHER_SUBJECT = "other-user";

    /**
     * Verifies that a user with a subject keeps it.
     */
    @Test
    void constructor_whenSubjectIsGiven_keepsIt() {
        assertEquals(SUBJECT, new SessionUser(SUBJECT).subject());
    }

    /**
     * Verifies that a null subject is rejected.
     */
    @Test
    void constructor_whenSubjectIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SessionUser(null));
    }

    /**
     * Verifies that a blank subject is rejected.
     */
    @Test
    void constructor_whenSubjectIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SessionUser("  "));
    }

    /**
     * Verifies that two users with the same subject are equal and two with different subjects are not.
     */
    @Test
    void equalsAndHashCode_whenSubjectsMatch_areEqual() {
        assertEquals(new SessionUser(SUBJECT), new SessionUser(SUBJECT));
        assertEquals(new SessionUser(SUBJECT).hashCode(), new SessionUser(SUBJECT).hashCode());
        assertNotEquals(new SessionUser(SUBJECT), new SessionUser(OTHER_SUBJECT));
    }
}
