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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.TrustedDeviceResponse;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TrustedDeviceDtoMapper}.
 */
class TrustedDeviceDtoMapperTest {

    /** Creation instant of the test devices. */
    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /** Lifetime of the test devices. */
    private static final Duration LIFETIME = Duration.ofDays(30);

    /** Mapper under test. */
    private final TrustedDeviceDtoMapper mapper = new TrustedDeviceDtoMapper();

    /**
     * Verifies that the public fields are copied and the token hash is not part of the answer.
     */
    @Test
    void toResponse_whenDeviceIsGiven_copiesItsPublicFields() {
        final var device = device("Firefox on Linux");

        final var response = mapper.toResponse(device);

        assertEquals(device.id(), response.id());
        assertEquals("Firefox on Linux", response.userAgentSummary());
        assertEquals(CREATED, response.createdAt());
        assertEquals(CREATED.plus(LIFETIME), response.expiresAt());
    }

    /**
     * Verifies that an unknown browser stays absent.
     */
    @Test
    void toResponse_whenSummaryIsAbsent_leavesItNull() {
        assertNull(mapper.toResponse(device(null)).userAgentSummary());
    }

    /**
     * Verifies that several devices keep their order.
     */
    @Test
    void toResponses_whenDevicesAreGiven_keepsTheirOrder() {
        final var first = device("a");
        final var second = device("b");

        final var responses = mapper.toResponses(List.of(first, second));

        assertEquals(List.of(first.id(), second.id()), responses.stream().map(TrustedDeviceResponse::id).toList());
    }

    /**
     * Builds a device.
     *
     * @param summary summary of its browser.
     * @return the device.
     */
    private static TrustedDevice device(final String summary) {
        return new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), "hash", summary, CREATED.plus(LIFETIME),
                CREATED);
    }
}
