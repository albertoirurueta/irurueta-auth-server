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

package com.irurueta.authserver.authorization.application.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CreatedTrustedDevice}.
 */
class CreatedTrustedDeviceTest {

    /**
     * Verifies that the components are kept.
     */
    @Test
    void constructor_whenCalled_keepsTheComponents() {
        final var now = Instant.parse("2026-01-01T00:00:00Z");
        final var device = new TrustedDevice(
                UUID.randomUUID(), UUID.randomUUID(), "hash", null, now.plusSeconds(1), now);

        final var created = new CreatedTrustedDevice(device, "token");

        assertSame(device, created.device());
        assertEquals("token", created.cookieValue());
    }
}
