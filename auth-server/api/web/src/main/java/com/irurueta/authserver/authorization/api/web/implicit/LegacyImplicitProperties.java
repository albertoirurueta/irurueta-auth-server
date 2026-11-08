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
package com.irurueta.authserver.authorization.api.web.implicit;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;

// tag::implicit-properties[]
/**
 * Settings of the legacy implicit flow, bound from {@code authserver.legacy-implicit.*} (see
 * {@code application-legacy-implicit.yml}). The flow exists only to show why OAuth 2.1 removed it, so it is limited to
 * one client, one redirect URI, a restricted audience and scope, and a short lifetime.
 *
 * @param clientId       identifier of the only client that may use the flow.
 * @param redirectUri    the only redirect URI of that client.
 * @param scopes         scopes the client may request.
 * @param audience       audience of the access tokens it gets.
 * @param accessTokenTtl lifetime of the access tokens, at most {@link #MAX_ACCESS_TOKEN_TTL}.
 */
@ConfigurationProperties(prefix = "authserver.legacy-implicit")
public record LegacyImplicitProperties(
        @DefaultValue("legacy-implicit-spa") String clientId,
        String redirectUri,
        @DefaultValue("documents.read") List<String> scopes,
        @DefaultValue("resource-server") String audience,
        @DefaultValue("PT5M") Duration accessTokenTtl) {

    /** Longest lifetime an access token of the legacy flow may have. */
    public static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofMinutes(15);

    /**
     * Validates the settings and defensively copies the scopes.
     *
     * @throws IllegalArgumentException if the client id, redirect URI or audience is blank, the scopes are missing,
     *                                  empty or contain a blank value, or the lifetime is missing, not positive or
     *                                  longer than {@link #MAX_ACCESS_TOKEN_TTL}.
     */
    public LegacyImplicitProperties {
        requireText(clientId, "clientId");
        requireText(redirectUri, "redirectUri");
        requireText(audience, "audience");
        if (scopes == null || scopes.isEmpty() || scopes.stream().anyMatch(scope -> !StringUtils.hasText(scope))) {
            throw new IllegalArgumentException("scopes must not be empty or contain blank values");
        }
        scopes = List.copyOf(scopes);
        if (accessTokenTtl == null || accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("accessTokenTtl must be positive");
        }
        if (accessTokenTtl.compareTo(MAX_ACCESS_TOKEN_TTL) > 0) {
            throw new IllegalArgumentException("accessTokenTtl must be at most " + MAX_ACCESS_TOKEN_TTL);
        }
    }

    /**
     * Refuses a blank text.
     *
     * @param value the value.
     * @param name  its name, for the message.
     */
    private static void requireText(final String value, final String name) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
// end::implicit-properties[]
