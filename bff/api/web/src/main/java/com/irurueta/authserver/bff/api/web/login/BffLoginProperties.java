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

package com.irurueta.authserver.bff.api.web.login;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration of the BFF login ({@code bff.login.*}).
 *
 * @param allowedReturnPaths relative paths the SPA may ask to return to after the login. An entry ending in
 *                           {@code /} (other than the root) also allows every path below it; any other entry
 *                           allows exactly that path. Never {@code null}; defaults to the root of the application
 *                           and its index page.
 */
@ConfigurationProperties(prefix = "bff.login")
public record BffLoginProperties(List<String> allowedReturnPaths) {

    /** Paths allowed when nothing is configured: the application root and its index page. */
    private static final List<String> DEFAULT_ALLOWED_RETURN_PATHS = List.of("/", "/index.html");

    /**
     * Applies the defaults and copies the list defensively.
     */
    public BffLoginProperties {
        allowedReturnPaths = allowedReturnPaths == null || allowedReturnPaths.isEmpty()
                ? DEFAULT_ALLOWED_RETURN_PATHS
                : List.copyOf(allowedReturnPaths);
    }
}
