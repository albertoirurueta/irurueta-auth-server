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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.application.mfa.CreatedTrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests of {@link TrustedDeviceCookieWriter}.
 */
class TrustedDeviceCookieWriterTest {

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Seconds the device stays trusted in the tests. */
    private static final long LIFETIME_SECONDS = 3600;

    /** Writer under test. */
    private final TrustedDeviceCookieWriter writer = new TrustedDeviceCookieWriter(Clock.fixed(NOW, ZoneOffset.UTC));

    /**
     * Verifies the attributes of the cookie: prefix rules, flags and a lifetime equal to the trust period.
     */
    @Test
    void write_whenDeviceIsTrusted_addsTheHostCookieWithTheFlags() {
        final var response = new MockHttpServletResponse();

        writer.write(response, created(NOW.plusSeconds(LIFETIME_SECONDS)));

        final var header = response.getHeader(HttpHeaders.SET_COOKIE);
        assertTrue(header.startsWith("__Host-TRUSTED-DEVICE=raw-token;"));
        assertTrue(header.contains("Max-Age=" + LIFETIME_SECONDS));
        assertTrue(header.contains("Path=/"));
        assertTrue(header.contains("Secure"));
        assertTrue(header.contains("HttpOnly"));
        assertTrue(header.contains("SameSite=Lax"));
        assertFalse(header.contains("Domain"));
    }

    /**
     * Verifies that a device that is already expired gets a cookie that does not outlive the response.
     */
    @Test
    void write_whenDeviceHasExpired_writesAZeroLifetime() {
        final var response = new MockHttpServletResponse();

        writer.write(response, created(NOW.minusSeconds(LIFETIME_SECONDS)));

        assertTrue(response.getHeader(HttpHeaders.SET_COOKIE).contains("Max-Age=0"));
        assertEquals("__Host-TRUSTED-DEVICE", TrustedDeviceCookieWriter.COOKIE_NAME);
    }

    /**
     * Builds a created device.
     *
     * @param expiresAt when the trust ends.
     * @return the device and its raw token.
     */
    private static CreatedTrustedDevice created(final Instant expiresAt) {
        return new CreatedTrustedDevice(new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), "hash", null,
                expiresAt, NOW), "raw-token");
    }
}
