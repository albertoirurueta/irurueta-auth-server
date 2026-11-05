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

package com.irurueta.authserver.authorization.api.web.clients;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the seeding of the default clients ({@code authserver.clients.*}).
 *
 * <p>Secrets come from the environment only and are never committed: the property resolves to an empty value when
 * the environment variable is not set, and a confidential client without a secret is then not seeded.
 *
 * @param bffSecret clear-text secret of the {@code bff} client; empty or {@code null} when not configured.
 */
@ConfigurationProperties(prefix = "authserver.clients")
public record ClientSeedProperties(String bffSecret) {

    @Override
    public String toString() {
        return "ClientSeedProperties[bffSecret=***]";
    }
}
