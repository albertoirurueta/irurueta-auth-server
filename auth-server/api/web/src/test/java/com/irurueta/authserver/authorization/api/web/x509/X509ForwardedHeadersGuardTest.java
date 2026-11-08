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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Unit tests of {@link X509ForwardedHeadersGuard}. The environment is Spring's in-memory {@link MockEnvironment}, a
 * real implementation used as test data.
 */
class X509ForwardedHeadersGuardTest {

    /** Name of the forwarded header of the tests. */
    private static final String HEADER = "X-Client-Cert";

    /** Property that forces a cloud platform. */
    private static final String CLOUD_PLATFORM = "spring.main.cloud-platform";

    /**
     * Verifies that the forwarded transport with the {@code framework} strategy stops the startup, naming the property.
     */
    @Test
    void constructor_whenForwardedAndFrameworkStrategy_throwsIllegalStateException() {
        final var environment = new MockEnvironment().withProperty(X509ForwardedHeadersGuard.STRATEGY_PROPERTY,
                "framework");

        final var error = assertThrows(IllegalStateException.class,
                () -> new X509ForwardedHeadersGuard(properties(HEADER), environment));

        assertTrue(error.getMessage().contains("server.forward-headers-strategy=none"), error.getMessage());
    }

    /**
     * Verifies that the forwarded transport with the {@code native} strategy, in any case, stops the startup.
     */
    @Test
    void constructor_whenForwardedAndNativeStrategy_throwsIllegalStateException() {
        final var environment = new MockEnvironment().withProperty(X509ForwardedHeadersGuard.STRATEGY_PROPERTY,
                "NATIVE");

        assertThrows(IllegalStateException.class,
                () -> new X509ForwardedHeadersGuard(properties(HEADER), environment));
    }

    /**
     * Verifies that the forwarded transport with the {@code none} strategy starts, even on a cloud platform.
     */
    @Test
    void constructor_whenForwardedAndNoneStrategy_doesNotThrow() {
        final var environment = new MockEnvironment()
                .withProperty(X509ForwardedHeadersGuard.STRATEGY_PROPERTY, "none")
                .withProperty(CLOUD_PLATFORM, "kubernetes");

        assertDoesNotThrow(() -> new X509ForwardedHeadersGuard(properties(HEADER), environment));
    }

    /**
     * Verifies that without the forwarded transport any strategy is accepted.
     */
    @Test
    void constructor_whenNotForwarded_doesNotThrow() {
        final var environment = new MockEnvironment().withProperty(X509ForwardedHeadersGuard.STRATEGY_PROPERTY,
                "framework");

        assertDoesNotThrow(() -> new X509ForwardedHeadersGuard(properties(""), environment));
    }

    /**
     * Verifies that without a strategy the address is left alone when no cloud platform is detected.
     */
    @Test
    void rewritesClientAddress_whenUnsetAndNoCloudPlatform_isFalse() {
        assertFalse(new X509ForwardedHeadersGuard(properties(""), new MockEnvironment()).rewritesClientAddress());
    }

    /**
     * Verifies that without a strategy a cloud platform that uses the forwarded headers rewrites the address.
     */
    @Test
    void rewritesClientAddress_whenUnsetOnACloudPlatform_isTrue() {
        final var environment = new MockEnvironment().withProperty(CLOUD_PLATFORM, "kubernetes");

        assertTrue(new X509ForwardedHeadersGuard(properties(""), environment).rewritesClientAddress());
    }

    /**
     * Builds the settings.
     *
     * @param header the forwarded header, empty for none.
     * @return the settings.
     */
    private static X509Properties properties(final String header) {
        return new X509Properties(true, header, List.of("192.0.2.0/24"), 0, "sc", "", "", "PKCS12");
    }
}
