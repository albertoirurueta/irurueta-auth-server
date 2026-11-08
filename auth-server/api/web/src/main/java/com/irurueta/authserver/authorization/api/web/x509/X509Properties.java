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

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.util.StringUtils;

// tag::x509-properties[]
/**
 * Configuration of the sign-in with a client certificate ({@code authserver.x509.*}). It is off by default.
 *
 * @param enabled           whether the sign-in with a client certificate exists at all (default {@code false}).
 * @param forwardedHeader   name of the request header in which a trusted reverse proxy forwards the client certificate
 *                          it verified (PEM, URL-encoded as {@code $ssl_client_escaped_cert} of nginx does, or the
 *                          base64 of the DER form); empty (the default) turns the forwarded transport off.
 * @param trustedProxies    addresses or CIDR ranges of the proxies that may forward a certificate; required when the
 *                          header is set, and a request from any other address never has its header read.
 * @param port              port of the dedicated TLS connector that requests a client certificate; {@code 0} (the
 *                          default) turns the direct transport off.
 * @param amr               RFC 8176 {@code amr} value the factor reports: {@code sc} (smart card, the default) or
 *                          {@code hwk} (a hardware-bound key).
 * @param keyStore          path of the key store with the server certificate of the dedicated port; with the
 *                          {@code dev} profile and none configured, a self-signed one is generated at the first start
 *                          under {@code ~/.irurueta-auth-server/}.
 * @param keyStorePassword  password of the key store (and of its key), from the environment, never from a file.
 * @param keyStoreType      type of the key store (default {@code PKCS12}).
 */
@ConfigurationProperties(prefix = "authserver.x509")
public record X509Properties(
        @DefaultValue("false") boolean enabled,
        @DefaultValue("") String forwardedHeader,
        @DefaultValue List<String> trustedProxies,
        @DefaultValue("0") int port,
        @DefaultValue("sc") String amr,
        @DefaultValue("") String keyStore,
        @DefaultValue("") String keyStorePassword,
        @DefaultValue("PKCS12") String keyStoreType) {

    /** {@code amr} value of a smart card. */
    public static final String AMR_SMART_CARD = "sc";

    /** {@code amr} value of a key held in hardware. */
    public static final String AMR_HARDWARE_KEY = "hwk";

    /** Highest TCP port. */
    private static final int MAX_PORT = 65_535;

    /**
     * Validates the configuration and copies the list.
     *
     * @throws IllegalArgumentException if the port is out of range, the {@code amr} value is not {@code sc} or
     *                                  {@code hwk}, a trusted proxy is not an address or a range, or a forwarded
     *                                  header is set without any trusted proxy.
     */
    public X509Properties {
        trustedProxies = List.copyOf(trustedProxies);
        if (port < 0 || port > MAX_PORT) {
            throw new IllegalArgumentException("port must be between 0 and " + MAX_PORT);
        }
        if (!AMR_SMART_CARD.equals(amr) && !AMR_HARDWARE_KEY.equals(amr)) {
            throw new IllegalArgumentException("amr must be " + AMR_SMART_CARD + " or " + AMR_HARDWARE_KEY);
        }
        trustedProxies.forEach(IpAddressMatcher::new);
        if (StringUtils.hasText(forwardedHeader) && trustedProxies.isEmpty()) {
            throw new IllegalArgumentException("a forwarded header needs at least one trusted proxy");
        }
    }

    /**
     * Tells whether the certificate may arrive in a header.
     *
     * @return {@code true} when a header name is configured.
     */
    public boolean forwardedEnabled() {
        return StringUtils.hasText(forwardedHeader);
    }

    /**
     * Tells whether the dedicated TLS connector is requested.
     *
     * @return {@code true} when a port is configured.
     */
    public boolean tlsEnabled() {
        return port > 0;
    }
}
// end::x509-properties[]
