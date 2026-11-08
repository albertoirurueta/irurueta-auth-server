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

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Private key with which the {@code private_key_jwt} assertion is signed ({@code service-client.auth.key.*}): an
 * unencrypted RSA key in PKCS#8 PEM, given inline (the CLI profiles read it from the {@code SERVICE_CLIENT_PRIVATE_KEY}
 * environment variable) or as the path of a file. The inline value wins when both are given.
 *
 * @param privateKey     the PEM text, or {@code null} / blank when there is none.
 * @param privateKeyPath path of a PEM file, or {@code null} when there is none.
 * @param keyId          {@code kid} written in the assertion header, or {@code null} to write none.
 */
@ConfigurationProperties(prefix = "service-client.auth.key")
public record ServiceClientKeyProperties(String privateKey, Path privateKeyPath, String keyId) {

    /**
     * Describes the settings without the key.
     *
     * @return the description.
     */
    @Override
    public String toString() {
        return "ServiceClientKeyProperties[privateKeyPath=" + privateKeyPath + ", keyId=" + keyId + "]";
    }
}
