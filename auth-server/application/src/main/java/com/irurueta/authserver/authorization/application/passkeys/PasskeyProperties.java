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

package com.irurueta.authserver.authorization.application.passkeys;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

// tag::passkeys-properties[]
/**
 * Relying party settings of the passkeys (WebAuthn), bound once from {@code authserver.passkeys.*} and injected
 * wherever one of them is needed. An invalid value stops the application at startup. A browser only accepts a
 * credential whose relying party id is the host of the page (or a registrable suffix of it) and whose origin is one of
 * the allowed ones, so a deployment must set {@code rp-id} and {@code allowed-origins} to its public host name; the
 * shipped {@code application.yml} defaults to {@code localhost} for local runs only.
 *
 * @param rpName         name of the relying party shown by the authenticator (default {@code Irurueta Auth Server}).
 * @param rpId           relying party id: the host name credentials are scoped to.
 * @param allowedOrigins origins (scheme, host and port) the browser may run the WebAuthn ceremonies from.
 */
@ConfigurationProperties("authserver.passkeys")
public record PasskeyProperties(
        @DefaultValue("Irurueta Auth Server") String rpName,
        String rpId,
        List<String> allowedOrigins) {

    /**
     * Validates the settings and copies the origins.
     *
     * @throws IllegalArgumentException if the name or the id is blank, or there is no allowed origin or one is blank.
     */
    public PasskeyProperties {
        if (rpName == null || rpName.isBlank()) {
            throw new IllegalArgumentException("authserver.passkeys.rp-name must not be blank");
        }
        if (rpId == null || rpId.isBlank()) {
            throw new IllegalArgumentException("authserver.passkeys.rp-id must not be blank");
        }
        if (allowedOrigins == null || allowedOrigins.isEmpty()
                || allowedOrigins.stream().anyMatch(origin -> origin == null || origin.isBlank())) {
            throw new IllegalArgumentException(
                    "authserver.passkeys.allowed-origins must list at least one origin and none may be blank");
        }
        allowedOrigins = List.copyOf(allowedOrigins);
    }
}
// end::passkeys-properties[]
