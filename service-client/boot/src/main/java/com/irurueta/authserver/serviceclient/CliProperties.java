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


package com.irurueta.authserver.serviceclient;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the {@code client-credentials} and {@code token-exchange} runners ({@code service-client.cli.*}).
 *
 * @param printAccessToken whether the runner also prints the access token it used ({@code false} by default: a token
 *                         is a credential and is never printed unless asked).
 * @param subjectToken     access token of the user for the {@code token-exchange} runner, normally read from the
 *                         {@code SERVICE_CLIENT_SUBJECT_TOKEN} environment variable.
 */
@ConfigurationProperties(prefix = "service-client.cli")
public record CliProperties(boolean printAccessToken, String subjectToken) {

    /**
     * Describes the settings without the token.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "CliProperties[printAccessToken=" + printAccessToken + "]";
    }
}
