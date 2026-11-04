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

package com.irurueta.authserver.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OpenApiConfigTest {

    private final OpenApiConfig config = new OpenApiConfig();

    @Test
    void authServerOpenApi_describesTheApi() {
        final var info = config.authServerOpenApi().getInfo();

        assertThat(info.getTitle()).isEqualTo("Irurueta Auth Server API");
        assertThat(info.getVersion()).isNotBlank();
        assertThat(info.getLicense().getName()).isEqualTo("Apache License 2.0");
    }

    @Test
    void apiGroup_matchesOnlyApiPaths() {
        final var group = config.apiGroup();

        assertThat(group.getGroup()).isEqualTo("api");
        assertThat(group.getPathsToMatch()).containsExactly("/api/**");
    }
}
