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
package com.irurueta.authserver.authorization.infrastructure.github;

import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.ApiClient;
import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.api.UsersApi;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

// tag::github-client-factory[]
/**
 * Builds the users client generated from the GitHub contract for one call. The generated {@link ApiClient} keeps its
 * base path and bearer token as mutable state, and both change with every sign-in (the base path comes from the
 * registration, the token from the user), so a shared instance would mix the calls of concurrent sign-ins: each call
 * gets its own client on top of one shared, thread-safe {@link RestClient}.
 */
@Component
public class GitHubUsersApiFactory {

    /** HTTP client every generated client sends its requests through. */
    private final RestClient restClient;

    /**
     * Creates the factory.
     *
     * @param builder builder of REST clients configured by Spring Boot (message converters, observations).
     */
    public GitHubUsersApiFactory(final RestClient.Builder builder) {
        restClient = builder.build();
    }

    /**
     * Builds the client of one call.
     *
     * @param basePath    base URI of GitHub's API, without a trailing slash.
     * @param accessToken GitHub access token of the user, sent as the bearer token.
     * @return the generated users client.
     */
    public UsersApi create(final String basePath, final String accessToken) {
        final var apiClient = new ApiClient(restClient).setBasePath(basePath);
        apiClient.setBearerToken(accessToken);
        return new UsersApi(apiClient);
    }
}
// end::github-client-factory[]
