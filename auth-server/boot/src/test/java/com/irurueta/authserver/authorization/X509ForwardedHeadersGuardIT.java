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
package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.x509.X509Factor;
import com.irurueta.authserver.authorization.api.web.x509.X509ForwardedHeadersGuard;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Checks, with the properties bound as the application binds them, that a certificate forwarded in a header is refused
 * at startup while {@code server.forward-headers-strategy} lets the forwarded headers rewrite the address of the client
 * (the address checked against the trusted proxies), and accepted with the strategy {@code none}.
 */
class X509ForwardedHeadersGuardIT {

    /** Runner of a context with the bound X.509 settings and the guard. */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(X509Factor.class)
            .withBean(X509ForwardedHeadersGuard.class)
            .withPropertyValues("authserver.x509.enabled=true", "authserver.x509.forwarded-header=X-Client-Cert",
                    "authserver.x509.trusted-proxies=192.0.2.10");

    /**
     * Verifies that the {@code framework} strategy stops the startup, naming the property.
     */
    @Test
    void startup_whenForwardedAndFrameworkStrategy_failsNamingTheStrategy() {
        runner.withPropertyValues("server.forward-headers-strategy=framework").run(context -> {
            final var failure = context.getStartupFailure();
            assertNotNull(failure, "The startup must fail");
            var cause = (Throwable) failure;
            while (cause.getCause() != null) {
                cause = cause.getCause();
            }
            assertInstanceOf(IllegalStateException.class, cause);
            assertTrue(cause.getMessage().contains("server.forward-headers-strategy=none"), cause.getMessage());
        });
    }

    /**
     * Verifies that the {@code native} strategy stops the startup.
     */
    @Test
    void startup_whenForwardedAndNativeStrategy_fails() {
        runner.withPropertyValues("server.forward-headers-strategy=native")
                .run(context -> assertNotNull(context.getStartupFailure(), "The startup must fail"));
    }

    /**
     * Verifies that the strategy {@code none} starts.
     */
    @Test
    void startup_whenForwardedAndNoneStrategy_starts() {
        runner.withPropertyValues("server.forward-headers-strategy=none")
                .run(context -> assertNull(context.getStartupFailure(), "The startup must not fail"));
    }
}
