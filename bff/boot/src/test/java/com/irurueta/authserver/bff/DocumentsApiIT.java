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

package com.irurueta.authserver.bff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Client;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.client.ExpectedCount.never;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.AutoConfigureMockRestServiceServer;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Integration tests of the documents API ({@code /api/documents}) through the whole filter chain, the controller, the
 * use cases and the generated resource-server client. The resource server is a {@link MockRestServiceServer} bound to
 * the {@code RestClient.Builder} the client is built from.
 */
@PostgresIT
@AutoConfigureMockMvc
@AutoConfigureMockRestServiceServer
class DocumentsApiIT {

    /** Access token of the session; it must reach the resource server and nobody else. */
    private static final String ACCESS_TOKEN = "documents-test-access-token";

    /** Minutes the access token of the session lives. */
    private static final long TOKEN_MINUTES = 5;

    /** Lifetime of the access token of the session. */
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(TOKEN_MINUTES);

    /** Documents of the resource server (the default of {@code bff.resource-server.base-uri}). */
    private static final String DOCUMENTS = "http://localhost:8081/api/documents";

    /** One document of the resource server. */
    private static final String DOCUMENT = DOCUMENTS + "/7";

    /** Path of the documents on the BFF. */
    private static final String BFF_DOCUMENTS = "/api/documents";

    /** Path of one document on the BFF. */
    private static final String BFF_DOCUMENT = BFF_DOCUMENTS + "/7";

    /** Media type of the problem details. */
    private static final String PROBLEM_JSON = MediaType.APPLICATION_PROBLEM_JSON_VALUE;

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /** Server standing in for the resource server. */
    @Autowired
    private MockRestServiceServer server;

    /**
     * Forgets the expectations of the previous test.
     */
    @BeforeEach
    void setUp() {
        server.reset();
    }

    /**
     * Verifies that the bearer token is sent to the resource server while the browser's credentials are not, and that
     * neither the token nor anything the resource server set in its headers reaches the browser.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenSignedIn_sendsTheBearerUpstreamAndKeepsItFromTheBrowser() throws Exception {
        server.expect(requestTo(DOCUMENTS))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer " + ACCESS_TOKEN))
                .andExpect(headerDoesNotExist("Cookie"))
                .andExpect(headerDoesNotExist("X-XSRF-TOKEN"))
                .andRespond(withSuccess("[{\"id\":\"1\",\"owner\":\"user\",\"title\":\"T\",\"content\":\"C\"}]",
                        MediaType.APPLICATION_JSON)
                        .header("Set-Cookie", "upstream=secret")
                        .header("Cache-Control", "max-age=3600"));

        final var result = mockMvc.perform(get(BFF_DOCUMENTS)
                        .header("Cookie", "other=1").header("X-XSRF-TOKEN", "browser-csrf")
                        .header("Authorization", "Bearer browser-supplied")
                        .with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isOk())
                .andExpect(content().json("[{\"id\":\"1\",\"owner\":\"user\",\"title\":\"T\",\"content\":\"C\"}]"))
                .andReturn().getResponse();

        server.verify();
        assertFalse(result.getHeaders("Set-Cookie").stream().anyMatch(value -> value.contains("upstream")));
        assertEquals(List.of("no-cache, no-store, max-age=0, must-revalidate"), result.getHeaders("Cache-Control"));
        assertNull(result.getHeader("Authorization"));
        assertFalse(result.getContentAsString().contains(ACCESS_TOKEN));
    }

    /**
     * Verifies that a deletion carrying the CSRF token reaches the resource server with the token and answers 204.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void deleteDocument_whenRequestHasCsrfToken_deletesUpstream() throws Exception {
        server.expect(requestTo(DOCUMENT))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header("Authorization", "Bearer " + ACCESS_TOKEN))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        mockMvc.perform(delete(BFF_DOCUMENT).with(csrf()).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isNoContent());

        server.verify();
    }

    /**
     * Verifies that a deletion without the CSRF token never reaches the resource server.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void deleteDocument_whenCsrfTokenIsMissing_isForbidden() throws Exception {
        server.expect(never(), requestTo(DOCUMENT)).andRespond(withStatus(HttpStatus.OK));

        mockMvc.perform(delete(BFF_DOCUMENT).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isForbidden());

        server.verify();
    }

    /**
     * Verifies that a missing document of the resource server is answered 404 as problem details.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void deleteDocument_whenResourceServerAnswersNotFound_answersNotFoundProblem() throws Exception {
        server.expect(requestTo(DOCUMENT)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        mockMvc.perform(delete(BFF_DOCUMENT).with(csrf()).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isNotFound())
                .andExpect(content().contentType(PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:documents:not-found"));
    }

    /**
     * Verifies that a refusal of the resource server is answered 403 as problem details, without its challenge or
     * its body.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenResourceServerForbids_answersForbiddenProblem() throws Exception {
        server.expect(requestTo(DOCUMENTS)).andRespond(withStatus(HttpStatus.FORBIDDEN)
                .header("WWW-Authenticate", "Bearer error=\"insufficient_scope\"").body("denied"));

        final var result = mockMvc.perform(get(BFF_DOCUMENTS).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:documents:forbidden"))
                .andReturn().getResponse();

        assertNull(result.getHeader("WWW-Authenticate"));
        assertFalse(result.getContentAsString().contains("denied"));
    }

    /**
     * Verifies that a token the resource server refuses is answered 401, so the SPA signs in again.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenResourceServerRefusesTheToken_answersUnauthorizedProblem() throws Exception {
        server.expect(requestTo(DOCUMENTS)).andRespond(withStatus(HttpStatus.UNAUTHORIZED));

        mockMvc.perform(get(BFF_DOCUMENTS).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").value("urn:problem:documents:unauthorized"));
    }

    /**
     * Verifies that a failing resource server is answered 502.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenResourceServerFails_answersBadGateway() throws Exception {
        server.expect(requestTo(DOCUMENTS)).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        mockMvc.perform(get(BFF_DOCUMENTS).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isBadGateway())
                .andExpect(content().contentType(PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:documents:unavailable"));
    }

    /**
     * Verifies that an unreachable resource server is answered 502.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenResourceServerIsUnreachable_answersBadGateway() throws Exception {
        server.expect(requestTo(DOCUMENTS)).andRespond(withException(new IOException("connection refused")));

        mockMvc.perform(get(BFF_DOCUMENTS).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isBadGateway());
    }

    /**
     * Verifies that an anonymous call gets a 401 and never reaches the resource server.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenCallerIsAnonymous_answersUnauthorized() throws Exception {
        server.expect(never(), requestTo(DOCUMENTS)).andRespond(withStatus(HttpStatus.OK));

        mockMvc.perform(get(BFF_DOCUMENTS)).andExpect(status().isUnauthorized());

        server.verify();
    }

    /**
     * Verifies that a session whose user has no authorized client is answered 401 and nothing is sent upstream.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void listDocuments_whenSessionHasNoToken_answersUnauthorized() throws Exception {
        server.expect(never(), requestTo(DOCUMENTS)).andRespond(withStatus(HttpStatus.OK));

        mockMvc.perform(get(BFF_DOCUMENTS).with(user("demo")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(PROBLEM_JSON));

        server.verify();
    }

    /**
     * Builds the post-processor that puts an authorized client with the test access token in the session.
     *
     * @return the request post-processor.
     */
    private static RequestPostProcessor signedInClient() {
        final var now = Instant.now();
        return oauth2Client("bff").accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN,
                now, now.plus(TOKEN_LIFETIME)));
    }
}
