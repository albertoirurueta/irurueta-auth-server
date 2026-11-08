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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Unit tests of {@link GitHubUsersApiFactory}: the generated client it builds calls the contract's path below the given
 * base URI with the user's token, against Spring's mock REST server (no network, no Spring context).
 */
class GitHubUsersApiFactoryTest {

    /** Base URI of the API. */
    private static final String BASE_PATH = "https://api.github.test";

    /** Builder the mock server is bound to. */
    private final RestClient.Builder builder = RestClient.builder();

    /** Mock server the clients talk to. */
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();

    /** Factory under test. */
    private final GitHubUsersApiFactory factory = new GitHubUsersApiFactory(builder);

    /**
     * Verifies that the client reads {@code /user/emails} below the base URI with the token as a bearer, and maps the
     * answer onto the generated model.
     */
    @Test
    void create_whenCalled_sendsTheTokenToTheEmailsEndpoint() {
        server.expect(requestTo(BASE_PATH + "/user/emails"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer token"))
                .andRespond(withSuccess("[{\"email\":\"main@example.org\",\"primary\":true,\"verified\":true}]",
                        MediaType.APPLICATION_JSON));

        final var emails = factory.create(BASE_PATH, "token").listEmailsForAuthenticatedUser();

        assertEquals(1, emails.size());
        assertEquals("main@example.org", emails.getFirst().getEmail());
        assertEquals(Boolean.TRUE, emails.getFirst().getPrimary());
        assertEquals(Boolean.TRUE, emails.getFirst().getVerified());
        server.verify();
    }

    /**
     * Verifies that each call gets its own client, so the token of one sign-in is never sent with another's.
     */
    @Test
    void create_whenCalledTwice_keepsTheTokensApart() {
        server.expect(requestTo(BASE_PATH + "/user/emails"))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer second"))
                .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
        final var first = factory.create(BASE_PATH, "first");

        final var emails = factory.create(BASE_PATH, "second").listEmailsForAuthenticatedUser();

        assertEquals(0, emails.size());
        assertEquals(BASE_PATH, first.getApiClient().getBasePath());
        server.verify();
    }

    /**
     * Verifies that an error status is reported as the REST client's exception, which the lookup handles.
     */
    @Test
    void create_whenGitHubFails_throwsRestClientResponseException() {
        server.expect(requestTo(BASE_PATH + "/user/emails")).andRespond(withServerError());
        final var api = factory.create(BASE_PATH, "token");

        assertThrows(RestClientResponseException.class, api::listEmailsForAuthenticatedUser);
    }
}
