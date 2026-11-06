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

package com.irurueta.authserver.bff.api.web;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Runtime OpenAPI document of the JSON API of the BFF, served by springdoc at {@value #API_DOCS_PATH} to a signed-in
 * user. The contract {@code apis/bff/rest-server/bff-api-v1.yaml} is the source of truth: the operations are
 * described by the interface generated from it, and this class only adds what springdoc cannot read from it (the
 * info block and the security scheme). {@code OpenApiDriftIT} fails when the document served differs from the
 * contract.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /** Path of the OpenAPI document. */
    public static final String API_DOCS_PATH = "/v3/api-docs";

    /** Name of the session-cookie security scheme the contract's operations refer to. */
    public static final String SESSION_SCHEME = "session";

    /** Name of the CSRF security scheme, which protects every state-changing request (the relayed ones included). */
    public static final String CSRF_SCHEME = "csrf";

    /** Name of the session cookie (set by {@code SessionConfiguration} of {@code bff/infrastructure/session}). */
    static final String SESSION_COOKIE = "__Host-SESSION";

    /** Name of the header carrying the CSRF token. */
    static final String CSRF_HEADER = "X-XSRF-TOKEN";

    /**
     * Describes the API.
     *
     * @return the OpenAPI info block and security scheme.
     */
    @Bean
    public OpenAPI bffOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Irurueta BFF API")
                        .description("JSON endpoints of the example backend for frontend.")
                        .version("1.0.0")
                        .license(new License().name("Apache License 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.txt")))
                .components(new Components()
                        .addSecuritySchemes(SESSION_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .name(SESSION_COOKIE))
                        .addSecuritySchemes(CSRF_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name(CSRF_HEADER)));
    }

    /**
     * Groups the BFF's own JSON paths, leaving out the OAuth 2.0 login endpoints.
     *
     * @return the group of API paths.
     */
    @Bean
    public GroupedOpenApi apiGroup() {
        return GroupedOpenApi.builder()
                .group("api")
                .pathsToMatch("/bff/**")
                .build();
    }
}
