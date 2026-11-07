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
package com.irurueta.authserver.authorization.domain.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link FederatedIdentity}.
 */
class FederatedIdentityTest {

    /** Link identifier used by the tests. */
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    /** Account identifier used by the tests. */
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");

    /** Subject used by the tests. */
    private static final String SUBJECT = "1234567890";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "user@example.com";

    /** Link instant used by the tests. */
    private static final Instant LINKED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Last sign-in instant used by the tests. */
    private static final Instant LAST_LOGIN_AT = Instant.parse("2026-02-01T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var identity = new FederatedIdentity(ID, USER_ID, IdentityProvider.GOOGLE, SUBJECT, EMAIL, LINKED_AT,
                LAST_LOGIN_AT);

        assertEquals(ID, identity.id());
        assertEquals(USER_ID, identity.userId());
        assertEquals(IdentityProvider.GOOGLE, identity.provider());
        assertEquals(SUBJECT, identity.subject());
        assertEquals(EMAIL, identity.email());
        assertEquals(LINKED_AT, identity.linkedAt());
        assertEquals(LAST_LOGIN_AT, identity.lastLoginAt());
    }

    /**
     * Verifies that the e-mail address and the last sign-in are optional.
     */
    @Test
    void constructor_whenOptionalValuesAreNull_acceptsThem() {
        final var identity = new FederatedIdentity(ID, USER_ID, IdentityProvider.GITHUB, SUBJECT, null, LINKED_AT,
                null);

        assertNull(identity.email());
        assertNull(identity.lastLoginAt());
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(null, USER_ID,
                IdentityProvider.GOOGLE, SUBJECT, EMAIL, LINKED_AT, null));
    }

    /**
     * Verifies that a missing account is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(ID, null,
                IdentityProvider.GOOGLE, SUBJECT, EMAIL, LINKED_AT, null));
    }

    /**
     * Verifies that a missing provider is rejected.
     */
    @Test
    void constructor_whenProviderIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(ID, USER_ID, null, SUBJECT, EMAIL,
                LINKED_AT, null));
    }

    /**
     * Verifies that a blank subject is rejected.
     */
    @Test
    void constructor_whenSubjectIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(ID, USER_ID,
                IdentityProvider.GOOGLE, " ", EMAIL, LINKED_AT, null));
    }

    /**
     * Verifies that a present but blank e-mail address is rejected.
     */
    @Test
    void constructor_whenEmailIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(ID, USER_ID,
                IdentityProvider.GOOGLE, SUBJECT, " ", LINKED_AT, null));
    }

    /**
     * Verifies that a missing link instant is rejected.
     */
    @Test
    void constructor_whenLinkedAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new FederatedIdentity(ID, USER_ID,
                IdentityProvider.GOOGLE, SUBJECT, EMAIL, null, null));
    }

    /**
     * Verifies the value semantics.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new FederatedIdentity(ID, USER_ID, IdentityProvider.APPLE, SUBJECT, EMAIL, LINKED_AT, null);
        final var second = new FederatedIdentity(ID, USER_ID, IdentityProvider.APPLE, SUBJECT, EMAIL, LINKED_AT,
                null);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, new FederatedIdentity(ID, USER_ID, IdentityProvider.APPLE, SUBJECT, EMAIL, LINKED_AT,
                LAST_LOGIN_AT));
    }
}
