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

package com.irurueta.authserver.resourceserver.api.web;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Runtime OpenAPI document of the HTTP API of the resource server, served by springdoc at {@value #API_DOCS_PATH}.
 * The contract {@code apis/resource-server/rest-server/resource-server-api-v1.yaml} is the source of truth: the
 * operations are described by the interface generated from it, and this class only adds what springdoc cannot read
 * from it (the info block and the security scheme). {@code OpenApiDriftIT} fails when the document served differs
 * from the contract.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /** Path of the OpenAPI document. */
    public static final String API_DOCS_PATH = "/v3/api-docs";

    /** Name of the bearer-token security scheme. */
    public static final String BEARER_SCHEME = "bearer";

    /**
     * Describes the API.
     *
     * @return the OpenAPI info block.
     */
    @Bean
    public OpenAPI resourceServerOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Irurueta Resource Server API")
                        .description("Protected REST API of the example resource server.")
                        .version("1.0.0")
                        .license(new License().name("Apache License 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.txt")))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")));
    }

    /**
     * Groups the application's own API paths.
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
