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
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;

/**
 * Response of the device authorization endpoint (RFC 8628 section 3.2).
 *
 * @param deviceCode              the code the CLI presents when polling; a secret, never printed.
 * @param userCode                the code the user types (or confirms) on the verification page.
 * @param verificationUri         the page where the user approves the request.
 * @param verificationUriComplete the same page with the user code included; may be {@code null} (optional in the RFC).
 * @param expiresIn               seconds the device code lives; the default when the server sends none or sends
 *                                {@code null}.
 * @param interval                minimum seconds between two polls; the default when the server sends none or
 *                                sends {@code null} (Spring Authorization Server does not send one).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DeviceAuthorization(
        @JsonProperty("device_code") String deviceCode,
        @JsonProperty("user_code") String userCode,
        @JsonProperty("verification_uri") String verificationUri,
        @JsonProperty("verification_uri_complete") String verificationUriComplete,
        @JsonProperty("expires_in") @JsonSetter(nulls = Nulls.AS_EMPTY) long expiresIn,
        @JsonProperty("interval") @JsonSetter(nulls = Nulls.AS_EMPTY) long interval) {

    /**
     * Lifetime assumed when the server does not say (the Spring Authorization Server default is five minutes).
     */
    public static final long DEFAULT_EXPIRES_IN_SECONDS = 300L;

    /**
     * Polling interval assumed when the server does not say (RFC 8628 section 3.2).
     */
    public static final long DEFAULT_INTERVAL_SECONDS = 5L;

    /**
     * Validates the mandatory members and applies the defaults of the optional ones.
     *
     * @param deviceCode              the device code.
     * @param userCode                the user code.
     * @param verificationUri         the verification page.
     * @param verificationUriComplete the verification page with the user code; optional.
     * @param expiresIn               seconds the device code lives; zero or negative means the default.
     * @param interval                seconds between polls; zero or negative means the default.
     */
    public DeviceAuthorization {
        if (isBlank(deviceCode) || isBlank(userCode) || isBlank(verificationUri)) {
            throw new DeviceFlowException("The device authorization response lacks device_code, user_code or "
                    + "verification_uri");
        }
        expiresIn = expiresIn > 0 ? expiresIn : DEFAULT_EXPIRES_IN_SECONDS;
        interval = interval > 0 ? interval : DEFAULT_INTERVAL_SECONDS;
    }

    /**
     * Describes the authorization without the device code, which is a secret.
     *
     * @return a description without secrets.
     */
    @Override
    public String toString() {
        return "DeviceAuthorization[userCode=" + userCode + ", verificationUri=" + verificationUri
                + ", expiresIn=" + expiresIn + ", interval=" + interval + "]";
    }

    /**
     * Tells whether a text is missing or blank.
     *
     * @param value the text.
     * @return {@code true} when it has no content.
     */
    private static boolean isBlank(final String value) {
        return value == null || value.isBlank();
    }
}
