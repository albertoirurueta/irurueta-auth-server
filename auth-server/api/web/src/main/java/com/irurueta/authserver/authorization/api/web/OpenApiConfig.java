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

package com.irurueta.authserver.authorization.api.web;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI documentation of the HTTP API of the authorization server. The OAuth 2.1 / OpenID Connect protocol
 * endpoints are defined by the specifications and documented by the discovery document, so only the application's
 * own REST endpoints are published here; the HTML pages (such as the login page) are hidden.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /** Path of the OpenAPI document. */
    public static final String API_DOCS_PATH = "/v3/api-docs";

    /**
     * Describes the API.
     *
     * @return the OpenAPI info block.
     */
    @Bean
    public OpenAPI authServerOpenApi() {
        return new OpenAPI().info(new Info()
                .title("Irurueta Auth Server API")
                .description("REST endpoints of the example OAuth 2.1 / OpenID Connect authorization server.")
                .version("1.0.0")
                .license(new License().name("Apache License 2.0")
                        .url("https://www.apache.org/licenses/LICENSE-2.0.txt")));
    }

    /**
     * Groups the application's own API paths, leaving out the protocol endpoints and the HTML pages.
     *
     * @return the group of API paths.
     */
    @Bean
    public GroupedOpenApi apiGroup() {
        return GroupedOpenApi.builder()
                .group("api")
                .pathsToMatch("/api/**")
                .build();
    }
}
