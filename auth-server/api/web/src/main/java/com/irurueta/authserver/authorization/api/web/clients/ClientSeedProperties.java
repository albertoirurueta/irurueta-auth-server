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

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the seeding of the default clients ({@code authserver.clients.*}).
 *
 * <p>Which clients are seeded, and where they redirect, is a property of the deployment: a client is seeded only when
 * its redirect URIs are configured, and nothing is configured by default (the {@code dev} profile sets the local
 * ones). Secrets come from the environment only and are never committed: the property resolves to an empty value
 * when the environment variable is not set, and a confidential client without a secret is then not seeded.
 *
 * @param bffSecret clear-text secret of the {@code bff} client; empty or {@code null} when not configured.
 * @param bff       seeding of the {@code bff} client; never {@code null} once constructed.
 * @param spaPublic seeding of the {@code spa-public} client; never {@code null} once constructed.
 */
@ConfigurationProperties(prefix = "authserver.clients")
public record ClientSeedProperties(String bffSecret, SeededClient bff, SeededClient spaPublic) {

    /**
     * Replaces a missing client section by an unconfigured one.
     */
    public ClientSeedProperties {
        bff = bff == null ? SeededClient.unconfigured() : bff;
        spaPublic = spaPublic == null ? SeededClient.unconfigured() : spaPublic;
    }

    @Override
    public String toString() {
        return "ClientSeedProperties[bffSecret=***, bff=" + bff + ", spaPublic=" + spaPublic + "]";
    }

    /**
     * Seeding of one default client.
     *
     * @param redirectUris redirect URIs of the client in this deployment; empty when the client is not seeded.
     */
    public record SeededClient(List<String> redirectUris) {

        /**
         * Copies the redirect URIs, treating a missing list as an empty one.
         */
        public SeededClient {
            redirectUris = redirectUris == null ? List.of() : List.copyOf(redirectUris);
        }

        /**
         * Creates the section of a client that is not seeded.
         *
         * @return a section without redirect URIs.
         */
        public static SeededClient unconfigured() {
            return new SeededClient(List.of());
        }

        /**
         * Tells whether the client is to be seeded.
         *
         * @return {@code true} when at least one redirect URI is configured.
         */
        public boolean isConfigured() {
            return !redirectUris.isEmpty();
        }
    }
}
