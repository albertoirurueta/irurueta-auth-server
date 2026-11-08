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

import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.ApiClient;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Builds the documents client generated from the resource server's contract on top of a REST client that sends the
 * access token of an authorized client (so the generated client's own authentication settings stay unused).
 */
@Component
@RequiredArgsConstructor
public class DocumentsApis {

    /** Template of the REST clients; it is never used itself, only copied (the builder is a prototype bean). */
    private final RestClient.Builder restClientBuilder;

    /** Where the resource server is. */
    private final ResourceServerProperties properties;

    /** Request factory over the SSL bundle, when there is one. */
    private final SslRequestFactories requestFactories;

    /** Interceptors that obtain and send the access token. */
    private final ResourceServerInterceptors interceptors;

    // tag::service-client-documents-client[]
    /**
     * Builds a documents client whose requests carry the access token of one authorized client.
     *
     * @param registrationId registration of the OAuth2 client that obtains the token.
     * @param principal      principal the token is cached under (the service client, or a user for a token exchange).
     * @return the documents client.
     */
    public DocumentsApi forPrincipal(final String registrationId, final Authentication principal) {
        final var builder = restClientBuilder.clone();
        requestFactories.create().ifPresent(builder::requestFactory);
        final var restClient = builder
                .requestInterceptors(list -> list.addAll(interceptors.create(registrationId, principal)))
                .build();
        final var apiClient = new ApiClient(restClient)
                .setBasePath(properties.baseUri().toString().replaceFirst("/+$", ""));
        return new DocumentsApi(apiClient);
    }
    // end::service-client-documents-client[]
}
