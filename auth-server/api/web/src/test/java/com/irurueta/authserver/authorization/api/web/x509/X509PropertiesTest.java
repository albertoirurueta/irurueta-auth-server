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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link X509Properties}.
 */
class X509PropertiesTest {

    /** A port. */
    private static final int PORT = 8443;

    /** A port above the range. */
    private static final int TOO_HIGH = 65_536;

    /** A range of proxies. */
    private static final String PROXIES = "192.0.2.0/24";

    /** Name of a header. */
    private static final String HEADER = "X-Client-Cert";

    /**
     * Verifies that a configuration with everything off is valid.
     */
    @Test
    void constructor_whenEverythingIsOff_isValidAndDisablesBothTransports() {
        final var properties = properties(false, "", List.of(), 0, "sc");

        assertFalse(properties.enabled());
        assertFalse(properties.forwardedEnabled());
        assertFalse(properties.tlsEnabled());
    }

    /**
     * Verifies that a header with trusted proxies enables the forwarded transport.
     */
    @Test
    void constructor_whenHeaderHasTrustedProxies_enablesTheForwardedTransport() {
        final var properties = properties(true, HEADER, List.of(PROXIES), 0, "hwk");

        assertTrue(properties.forwardedEnabled());
        assertEquals(List.of(PROXIES), properties.trustedProxies());
        assertEquals("hwk", properties.amr());
    }

    /**
     * Verifies that a port enables the direct transport.
     */
    @Test
    void constructor_whenPortIsSet_enablesTheTlsTransport() {
        assertTrue(properties(true, "", List.of(), PORT, "sc").tlsEnabled());
    }

    /**
     * Verifies that a header without any trusted proxy is refused, so a misconfiguration cannot open a spoofing hole.
     */
    @Test
    void constructor_whenHeaderHasNoTrustedProxy_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> properties(true, HEADER, List.of(), 0, "sc"));
    }

    /**
     * Verifies that a trusted proxy that is not an address is refused.
     */
    @Test
    void constructor_whenTrustedProxyIsNotAnAddress_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> properties(true, HEADER, List.of("not a proxy/99"), 0, "sc"));
    }

    /**
     * Verifies that a port out of range is refused.
     */
    @Test
    void constructor_whenPortIsOutOfRange_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> properties(true, "", List.of(), -1, "sc"));
        assertThrows(IllegalArgumentException.class, () -> properties(true, "", List.of(), TOO_HIGH, "sc"));
    }

    /**
     * Verifies that an {@code amr} value other than the two supported is refused.
     */
    @Test
    void constructor_whenAmrIsUnknown_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> properties(true, "", List.of(), 0, "pwd"));
    }

    /**
     * Verifies that the list of proxies is copied.
     */
    @Test
    void constructor_whenTheListIsChanged_keepsItsOwnCopy() {
        final var proxies = new ArrayList<>(List.of(PROXIES));
        final var properties = properties(true, HEADER, proxies, 0, "sc");

        proxies.clear();

        assertEquals(List.of(PROXIES), properties.trustedProxies());
    }

    /**
     * Builds properties.
     *
     * @param enabled whether the sign-in is enabled.
     * @param header  the forwarded header.
     * @param proxies the trusted proxies.
     * @param port    the TLS port.
     * @param amr     the {@code amr} value.
     * @return the properties.
     */
    private static X509Properties properties(final boolean enabled, final String header, final List<String> proxies,
            final int port, final String amr) {
        return new X509Properties(enabled, header, proxies, port, amr, "", "", "PKCS12");
    }
}
