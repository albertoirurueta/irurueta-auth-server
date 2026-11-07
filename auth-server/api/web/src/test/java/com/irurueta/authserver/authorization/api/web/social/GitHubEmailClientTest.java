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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Unit tests of {@link GitHubEmailClient}, against Spring's mock REST server (no network, no Spring context).
 */
class GitHubEmailClientTest {

    /** User endpoint of the registration. */
    private static final String USER_URI = "https://api.github.test/user";

    /** Mock server and client under test, built together. */
    private final RestClient.Builder builder = RestClient.builder();

    /** Mock server the client talks to. */
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();

    /** Client under test. */
    private final GitHubEmailClient client = new GitHubEmailClient(builder.build());

    /**
     * Verifies that the primary address is chosen only when it is verified, with the token as a bearer.
     */
    @Test
    void verifiedPrimaryEmail_whenPrimaryIsVerified_returnsIt() {
        server.expect(requestTo(USER_URI + "/emails"))
                .andExpect(header("Authorization", "Bearer token"))
                .andExpect(header("Accept", GitHubEmailClient.GITHUB_MEDIA_TYPE))
                .andRespond(withSuccess("""
                        [{"email":"other@example.org","primary":false,"verified":true},
                         {"email":"main@example.org","primary":true,"verified":true}]""",
                        MediaType.APPLICATION_JSON));

        assertEquals("main@example.org", client.verifiedPrimaryEmail(USER_URI, "token").orElseThrow());
        server.verify();
    }

    /**
     * Verifies that an unverified primary address is not returned, nor is a verified one that is not primary.
     */
    @Test
    void verifiedPrimaryEmail_whenPrimaryIsNotVerified_isEmpty() {
        server.expect(requestTo(USER_URI + "/emails"))
                .andRespond(withSuccess("""
                        [{"email":"main@example.org","primary":true,"verified":false},
                         {"email":"other@example.org","primary":false,"verified":true}]""",
                        MediaType.APPLICATION_JSON));

        assertTrue(client.verifiedPrimaryEmail(USER_URI, "token").isEmpty());
    }

    /**
     * Verifies that an entry whose address is not text is ignored.
     */
    @Test
    void verifiedPrimaryEmail_whenAddressIsNotText_isEmpty() {
        server.expect(requestTo(USER_URI + "/emails"))
                .andRespond(withSuccess("[{\"email\":1,\"primary\":true,\"verified\":true}]",
                        MediaType.APPLICATION_JSON));

        assertTrue(client.verifiedPrimaryEmail(USER_URI, "token").isEmpty());
    }

    /**
     * Verifies that an empty body is no address.
     */
    @Test
    void verifiedPrimaryEmail_whenBodyIsEmpty_isEmpty() {
        server.expect(requestTo(USER_URI + "/emails")).andRespond(withSuccess());

        assertTrue(client.verifiedPrimaryEmail(USER_URI, "token").isEmpty());
    }

    /**
     * Verifies that a failure of GitHub is no address rather than an error.
     */
    @Test
    void verifiedPrimaryEmail_whenGitHubFails_isEmpty() {
        server.expect(requestTo(USER_URI + "/emails")).andRespond(withServerError());

        assertFalse(client.verifiedPrimaryEmail(USER_URI, "token").isPresent());
    }
}
