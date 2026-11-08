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
package com.irurueta.authserver.authorization.api.web.clientauth;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;

// tag::clientauth-mtls-properties[]
/**
 * Configuration of the mutual-TLS client authentication ({@code authserver.mtls.*}, RFC 8705).
 *
 * @param trustedAuthorities paths of the PEM files whose certificates are the trust anchors of
 *                           {@code tls_client_auth}; empty (the default) means that no CA-issued client certificate
 *                           is accepted, and only {@code self_signed_tls_client_auth} can succeed.
 */
@ConfigurationProperties(prefix = "authserver.mtls")
public record MtlsProperties(@DefaultValue List<String> trustedAuthorities) {

    /**
     * Validates the configuration and copies the list.
     *
     * @throws IllegalArgumentException if a path is blank.
     */
    public MtlsProperties {
        trustedAuthorities = trustedAuthorities == null ? List.of() : List.copyOf(trustedAuthorities);
        if (trustedAuthorities.stream().anyMatch(path -> !StringUtils.hasText(path))) {
            throw new IllegalArgumentException("authserver.mtls.trusted-authorities must not contain a blank path");
        }
    }
}
// end::clientauth-mtls-properties[]
