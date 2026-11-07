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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Calls the standard device flow endpoints of the authorization server. They belong to Spring Authorization
 * Server, so there is no contract of ours to generate a client from.
 */
@Component
@Profile(DeviceFlowConfiguration.PROFILE)
@RequiredArgsConstructor
public class DeviceAuthorizationClient {

    /**
     * Path of the device authorization endpoint.
     */
    public static final String DEVICE_AUTHORIZATION_PATH = "/oauth2/device_authorization";

    /**
     * Path of the token endpoint.
     */
    public static final String TOKEN_PATH = "/oauth2/token";

    /**
     * Grant type of the token request (RFC 8628 section 3.4).
     */
    public static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /**
     * Error code meaning the user has not decided yet.
     */
    public static final String AUTHORIZATION_PENDING = "authorization_pending";

    /**
     * Error code meaning the client polls too fast.
     */
    public static final String SLOW_DOWN = "slow_down";

    /** The invalid response. */
    private static final String INVALID_RESPONSE = "invalid_response";

    /** The rest client. */
    private final RestClient restClient;

    /** The properties. */
    private final DeviceFlowProperties properties;

    /**
     * Asks the server for a device code and a user code.
     *
     * @return the authorization the user has to approve.
     * @throws DeviceFlowException if the request fails or the answer is unusable.
     */
    public DeviceAuthorization requestDeviceAuthorization() {
        final var form = new LinkedMultiValueMap<String, String>();
        form.add("client_id", properties.clientId());
        form.add("scope", properties.scope());
        try {
            final var body = restClient.post()
                    .uri(DEVICE_AUTHORIZATION_PATH)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .retrieve()
                    .body(DeviceAuthorization.class);
            if (body == null) {
                throw new DeviceFlowException("The device authorization response is empty");
            }
            return body;
        } catch (final RestClientException e) {
            throw new DeviceFlowException("The device authorization request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Polls the token endpoint once.
     *
     * @param deviceCode the device code returned by {@link #requestDeviceAuthorization()}.
     * @return what the server answered.
     * @throws DeviceFlowException if the server cannot be reached or the answer is not an OAuth response.
     */
    public PollOutcome pollToken(final String deviceCode) {
        final MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", DEVICE_CODE_GRANT);
        form.add("device_code", deviceCode);
        form.add("client_id", properties.clientId());
        try {
            return restClient.post()
                    .uri(TOKEN_PATH)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(form)
                    .exchange((request, response) -> {
                        if (response.getStatusCode().is2xxSuccessful()) {
                            final var token = response.bodyTo(TokenResponse.class);
                            return token == null ? new PollOutcome.Failed(INVALID_RESPONSE, "empty token response")
                                    : new PollOutcome.Granted(token);
                        }
                        return toOutcome(response.bodyTo(OAuthError.class));
                    });
        } catch (final RestClientException e) {
            throw new DeviceFlowException("The token request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Maps an error response of the token endpoint to a poll outcome.
     *
     * @param error the error response; may be {@code null}.
     * @return the outcome.
     */
    private PollOutcome toOutcome(final OAuthError error) {
        if (error == null || error.error() == null) {
            return new PollOutcome.Failed(INVALID_RESPONSE, "the error response has no error code");
        }
        return switch (error.error()) {
            case AUTHORIZATION_PENDING -> new PollOutcome.Pending();
            case SLOW_DOWN -> new PollOutcome.SlowDown();
            default -> new PollOutcome.Failed(error.error(), error.errorDescription());
        };
    }

    /**
     * Error response of the token endpoint (RFC 6749 section 5.2).
     *
     * @param error            the error code.
     * @param errorDescription the optional description.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record OAuthError(
            @JsonProperty("error") String error,
            @JsonProperty("error_description") String errorDescription) {
    }
}
