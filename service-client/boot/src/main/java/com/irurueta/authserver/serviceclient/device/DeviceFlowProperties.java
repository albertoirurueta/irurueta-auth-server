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

package com.irurueta.authserver.serviceclient.device;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * Settings of the device flow CLI, bound from {@code device-flow.*} (command-line arguments or environment
 * variables such as {@code DEVICE_FLOW_ISSUER}).
 *
 * @param issuer           base URL of the authorization server, for example {@code http://localhost:9000}; mandatory.
 * @param clientId         the public client; {@value #DEFAULT_CLIENT_ID} when blank.
 * @param scope            scopes requested, separated by spaces; {@value #DEFAULT_SCOPE} when blank.
 * @param printAccessToken whether the final output also carries the access token; off unless a caller needs it.
 */
@ConfigurationProperties("device-flow")
public record DeviceFlowProperties(URI issuer, String clientId, String scope, boolean printAccessToken) {

    /**
     * The public client the development data seeds for this flow.
     */
    public static final String DEFAULT_CLIENT_ID = "device-client";

    /**
     * Scopes the seeded client may request.
     */
    public static final String DEFAULT_SCOPE = "profile documents.read";

    /**
     * Validates the issuer and applies the defaults.
     *
     * @param issuer           base URL of the authorization server.
     * @param clientId         the public client.
     * @param scope            scopes requested.
     * @param printAccessToken whether the access token is printed.
     */
    public DeviceFlowProperties {
        if (issuer == null) {
            throw new IllegalArgumentException("device-flow.issuer is required");
        }
        clientId = StringUtils.hasText(clientId) ? clientId : DEFAULT_CLIENT_ID;
        scope = StringUtils.hasText(scope) ? scope : DEFAULT_SCOPE;
    }
}
