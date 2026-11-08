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

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.ConsentPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.DevSmsInboxPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.DeviceVerificationPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.IdentitiesPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.LoginPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.LogoutPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.PasskeysPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.PhonePageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.RecoveryCodesPageApi;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.SecondFactorPageApi;
import io.swagger.v3.oas.models.security.SecurityScheme;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Runtime OpenAPI documents of the authorization server, served by springdoc. The contracts under
 * {@code apis/auth-server/} are the source of truth: the operations are described by the interfaces generated from
 * them, and this class only adds what springdoc cannot read from those (the info blocks and the security schemes).
 * Two groups are published: {@value #API_GROUP} ({@code /api/**}, the REST API of
 * {@code rest-server/auth-server-api-v1.yaml}) and {@value #PAGES_GROUP} (the HTML pages of
 * {@code web-pages/auth-server-pages-v1.yaml}, at {@value #PAGES_DOCS_PATH}). {@code OpenApiDriftIT} fails when a
 * document served differs from its contract. The OAuth 2.1 / OpenID Connect protocol endpoints are defined by the
 * specifications and documented by the discovery document, so they are not published here.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    /** Path of the OpenAPI document. */
    public static final String API_DOCS_PATH = "/v3/api-docs";

    /** Name of the group of the REST API. */
    public static final String API_GROUP = "api";

    /** Name of the group of the HTML pages. */
    public static final String PAGES_GROUP = "pages";

    /** Path of the OpenAPI document of the HTML pages. */
    public static final String PAGES_DOCS_PATH = API_DOCS_PATH + "/" + PAGES_GROUP;

    /** Name of the bearer-token security scheme the REST contract's operations refer to. */
    public static final String BEARER_SCHEME = "bearer";

    /** Name of the session-cookie security scheme the pages contract's operations refer to. */
    public static final String SESSION_SCHEME = "session";

    /** Name of the session cookie (see {@code LogoutChainCustomizer}, which deletes it). */
    static final String SESSION_COOKIE = "JSESSIONID";

    /**
     * Describes the API.
     *
     * @return the OpenAPI info block.
     */
    @Bean
    public OpenAPI authServerOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Irurueta Auth Server API")
                        .description("REST endpoints of the example OAuth 2.1 / OpenID Connect authorization server.")
                        .version("1.0.0")
                        .license(license()))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")));
    }

    /**
     * Groups the application's own API paths, leaving out the protocol endpoints and the HTML pages.
     *
     * @return the group of API paths.
     */
    @Bean
    public GroupedOpenApi apiGroup() {
        return GroupedOpenApi.builder()
                .group(API_GROUP)
                .pathsToMatch("/api/**")
                .build();
    }

    // tag::pages-openapi-group[]
    /**
     * Groups the HTML pages of the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml}, with their
     * own info block and the session-cookie scheme instead of the REST API's.
     *
     * @return the group of the HTML pages.
     */
    @Bean
    public GroupedOpenApi pagesGroup() {
        return GroupedOpenApi.builder()
                .group(PAGES_GROUP)
                .pathsToMatch(LoginPageApi.PATH_LOGIN_PAGE, SecondFactorPageApi.PATH_SECOND_FACTOR_PAGE,
                        RecoveryCodesPageApi.PATH_RECOVERY_CODES_PAGE, ConsentPageApi.PATH_CONSENT_PAGE,
                        LogoutPageApi.PATH_LOGOUT_PAGE, PasskeysPageApi.PATH_PASSKEYS_PAGE,
                        PhonePageApi.PATH_PHONE_PAGE, PhonePageApi.PATH_VERIFY_PHONE_PAGE,
                        PhonePageApi.PATH_REMOVE_PHONE_PAGE,
                        IdentitiesPageApi.PATH_IDENTITIES_PAGE, IdentitiesPageApi.PATH_LINK_IDENTITY_PAGE,
                        OneTimeTokenPageApi.PATH_OTT_CODE_PAGE, OneTimeTokenPageApi.PATH_OTT_CONFIRM_PAGE,
                        DeviceVerificationPageApi.PATH_DEVICE_VERIFICATION_PAGE,
                        DevSmsInboxPageApi.PATH_DEV_SMS_INBOX_PAGE)
                .addOpenApiCustomizer(openApi -> {
                    final var components = Objects.requireNonNullElseGet(openApi.getComponents(), Components::new);
                    components.setSecuritySchemes(new LinkedHashMap<>(Map.of(SESSION_SCHEME, new SecurityScheme()
                            .type(SecurityScheme.Type.APIKEY)
                            .in(SecurityScheme.In.COOKIE)
                            .name(SESSION_COOKIE))));
                    openApi.info(new Info()
                            .title("Irurueta Auth Server Pages")
                            .description("Server-rendered HTML pages of the example OAuth 2.1 / OpenID Connect "
                                    + "authorization server.")
                            .version("1.0.0")
                            .license(license()))
                            .components(components);
                })
                .build();
    }
    // end::pages-openapi-group[]

    /**
     * Describes the license of the documents.
     *
     * @return the license.
     */
    private static License license() {
        return new License().name("Apache License 2.0").url("https://www.apache.org/licenses/LICENSE-2.0.txt");
    }
}
