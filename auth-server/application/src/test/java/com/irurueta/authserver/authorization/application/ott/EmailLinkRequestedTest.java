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
package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link EmailLinkRequested}.
 */
class EmailLinkRequestedTest {

    /** Address used by the tests. */
    private static final String ADDRESS = "alice@example.test";

    /** Link used by the tests. */
    private static final URI LINK = URI.create("https://auth.example.test/login/ott/confirm?token=secret-token");

    /** Validity used by the tests. */
    private static final Duration VALID_FOR = Duration.ofMinutes(15);

    /**
     * Verifies that a valid event keeps its values.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var event = new EmailLinkRequested(ADDRESS, LINK, VALID_FOR);

        assertEquals(ADDRESS, event.address());
        assertEquals(LINK, event.link());
        assertEquals(VALID_FOR, event.validFor());
    }

    /**
     * Verifies that missing or blank values are rejected.
     */
    @Test
    void constructor_whenAValueIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new EmailLinkRequested(null, LINK, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailLinkRequested(" ", LINK, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailLinkRequested(ADDRESS, null, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailLinkRequested(ADDRESS, LINK, null));
    }

    /**
     * Verifies that the description carries neither the address nor the link.
     */
    @Test
    void toString_whenCalled_hidesTheAddressAndTheLink() {
        final var text = new EmailLinkRequested(ADDRESS, LINK, VALID_FOR).toString();

        assertFalse(text.contains(ADDRESS));
        assertFalse(text.contains("secret-token"));
    }
}
