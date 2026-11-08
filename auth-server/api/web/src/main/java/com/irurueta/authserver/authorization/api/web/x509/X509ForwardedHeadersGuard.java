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

import java.util.Locale;
import org.springframework.boot.cloud.CloudPlatform;
import org.springframework.core.env.Environment;

// tag::x509-forwarded-headers-guard[]
/**
 * Refuses to start when a certificate may be forwarded in a header while the server rewrites the address of its
 * clients from the forwarded headers.
 *
 * <p>{@link ForwardedCertificateFilter} trusts a forwarded certificate only from the addresses of
 * {@code authserver.x509.trusted-proxies}, and it reads the address with {@code getRemoteAddr()}, which is the address
 * left once Spring Boot's forwarded-header handling has run. With {@code server.forward-headers-strategy=framework},
 * Spring's {@code ForwardedHeaderFilter} replaces it with the first value of {@code X-Forwarded-For} (or
 * {@code Forwarded}), which any client can send: naming a trusted proxy there would make a forged certificate header
 * look trusted. With {@code native}, Tomcat's {@code RemoteIpValve} replaces it with the client the proxies report,
 * so the address of the proxy itself is never seen and the check is made against an address that came from a header.
 * The same happens without the property on a cloud platform that Spring Boot detects, where {@code native} is the
 * default. Only with {@code none} is the address the direct network peer, which no header can change, so that is the
 * one combination allowed. The proxy is still free to send {@code X-Forwarded-*} headers; they are just not used.
 */
public final class X509ForwardedHeadersGuard {

    /** Property of Spring Boot that selects how the forwarded headers are handled. */
    static final String STRATEGY_PROPERTY = "server.forward-headers-strategy";

    /** Value of the strategy that leaves the address of the client alone. */
    private static final String NONE = "none";

    /** Value of the strategy of the servlet container. */
    private static final String NATIVE = "native";

    /** Value of the strategy of Spring's filter. */
    private static final String FRAMEWORK = "framework";

    /** Environment of the application, with the forwarded-header strategy. */
    private final Environment environment;

    /**
     * Checks the configuration.
     *
     * @param properties  settings of the sign-in with a certificate.
     * @param environment environment of the application, with the forwarded-header strategy.
     * @throws IllegalStateException if the forwarded certificate header is enabled and the strategy (configured or
     *                               deduced from the cloud platform) rewrites the address of the client.
     */
    public X509ForwardedHeadersGuard(final X509Properties properties, final Environment environment) {
        this.environment = environment;
        if (properties.forwardedEnabled() && rewritesClientAddress()) {
            throw new IllegalStateException("authserver.x509.forwarded-header needs " + STRATEGY_PROPERTY + "=" + NONE
                    + ": with any other strategy the address checked against authserver.x509.trusted-proxies comes "
                    + "from a forwarded header that a client can choose");
        }
    }

    /**
     * Tells whether the server replaces the address of its clients with one taken from the forwarded headers.
     *
     * @return {@code true} for the {@code native} and {@code framework} strategies, and without a strategy when the
     *         detected cloud platform uses the forwarded headers.
     */
    public boolean rewritesClientAddress() {
        final var strategy = environment.getProperty(STRATEGY_PROPERTY, "").strip().toLowerCase(Locale.ROOT);
        return switch (strategy) {
            case NATIVE, FRAMEWORK -> true;
            case NONE -> false;
            default -> {
                final var platform = CloudPlatform.getActive(environment);
                yield platform != null && platform.isUsingForwardHeaders();
            }
        };
    }
}
// end::x509-forwarded-headers-guard[]
