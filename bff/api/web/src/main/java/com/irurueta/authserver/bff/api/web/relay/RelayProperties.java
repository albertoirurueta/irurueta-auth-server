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
package com.irurueta.authserver.bff.api.web.relay;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the token relay ({@code bff.relay.*}).
 *
 * @param targetUri base URI of the resource server the {@code /api/**} calls are relayed to. Never {@code null};
 *                  defaults to {@code http://localhost:8081}.
 */
@ConfigurationProperties(prefix = "bff.relay")
public record RelayProperties(URI targetUri) {

    /** Target used when nothing is configured. */
    private static final URI DEFAULT_TARGET_URI = URI.create("http://localhost:8081");

    /**
     * Applies the default target.
     */
    public RelayProperties {
        targetUri = targetUri == null ? DEFAULT_TARGET_URI : targetUri;
    }
}
