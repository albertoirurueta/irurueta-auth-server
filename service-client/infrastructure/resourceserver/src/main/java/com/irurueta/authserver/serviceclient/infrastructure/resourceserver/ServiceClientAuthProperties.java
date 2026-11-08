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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the service client at the authorization server ({@code service-client.auth.*}). Every one has a default
 * so that the application starts under any profile; the CLI profiles supply the real values.
 *
 * @param method        how the client authenticates, {@code client_secret_basic} by default.
 * @param clientId      identifier of the client, {@code service-client} by default.
 * @param clientSecret  shared secret of {@code client_secret_basic}; empty for the other methods.
 * @param tokenUri      token endpoint, {@code http://localhost:9000/oauth2/token} by default.
 * @param scopes        scopes requested, {@code documents.read} by default.
 * @param refreshBefore how long before its expiry a cached access token is renewed, {@code PT60S} by default.
 * @param dpop          whether tokens are bound to a proof-of-possession key (RFC 9449).
 * @param sslBundle     name of the Spring Boot SSL bundle that holds the client certificate and the trust material;
 *                      needed by the mutual TLS methods (it is also used for the calls to the resource server), and
 *                      used by the other methods only when set.
 */
@ConfigurationProperties(prefix = "service-client.auth")
public record ServiceClientAuthProperties(AuthMethod method, String clientId, String clientSecret, URI tokenUri,
        List<String> scopes, Duration refreshBefore, boolean dpop, String sslBundle) {

    /** Client identifier used when nothing is configured. */
    public static final String DEFAULT_CLIENT_ID = "service-client";

    /** Token endpoint used when nothing is configured. */
    public static final URI DEFAULT_TOKEN_URI = URI.create("http://localhost:9000/oauth2/token");

    /** Scope requested when nothing is configured. */
    public static final String DEFAULT_SCOPE = "documents.read";

    /** Seconds before the expiry of a token at which it is renewed, when nothing is configured. */
    public static final long DEFAULT_REFRESH_BEFORE_SECONDS = 60L;

    /**
     * Applies the defaults and validates the values.
     *
     * @throws IllegalArgumentException if the refresh margin is negative.
     */
    public ServiceClientAuthProperties {
        method = method == null ? AuthMethod.CLIENT_SECRET_BASIC : method;
        clientId = clientId == null || clientId.isBlank() ? DEFAULT_CLIENT_ID : clientId;
        clientSecret = clientSecret == null ? "" : clientSecret;
        tokenUri = tokenUri == null ? DEFAULT_TOKEN_URI : tokenUri;
        scopes = scopes == null || scopes.isEmpty() ? List.of(DEFAULT_SCOPE) : List.copyOf(scopes);
        refreshBefore = refreshBefore == null ? Duration.ofSeconds(DEFAULT_REFRESH_BEFORE_SECONDS) : refreshBefore;
        if (refreshBefore.isNegative()) {
            throw new IllegalArgumentException("service-client.auth.refresh-before must not be negative");
        }
    }

    /**
     * Describes the settings without the secret.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "ServiceClientAuthProperties[method=" + method + ", clientId=" + clientId + ", tokenUri=" + tokenUri
                + ", scopes=" + scopes + ", refreshBefore=" + refreshBefore + ", dpop=" + dpop + ", sslBundle="
                + sslBundle + "]";
    }
}
