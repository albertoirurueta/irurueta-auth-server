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
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.time.Duration;
import java.time.Instant;
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
 * Integration tests of the token relay ({@code /api/**}) through the whole filter chain. The resource server is a
 * {@link MockRestServiceServer} bound to the {@code RestClient.Builder} the relay client is built from.
 */
@PostgresIT
@AutoConfigureMockMvc
@AutoConfigureMockRestServiceServer
class ApiRelayIT {

    /** Access token of the session; it must reach the resource server and nobody else. */
    private static final String ACCESS_TOKEN = "relay-test-access-token";

    /** Minutes the access token of the session lives. */
    private static final long TOKEN_MINUTES = 5;

    /** Lifetime of the access token of the session. */
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(TOKEN_MINUTES);

    /** Base URI of the resource server (the default of {@code bff.relay.target-uri}). */
    private static final String TARGET = "http://localhost:8081";

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
     * Verifies that the bearer token is sent upstream while browser credentials are not, and that neither the token
     * nor the cookies the resource server tried to set reach the browser.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenSignedIn_addsBearerUpstreamAndKeepsItFromTheBrowser() throws Exception {
        server.expect(requestTo(TARGET + "/api/documents?page=1"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer " + ACCESS_TOKEN))
                .andExpect(headerDoesNotExist("Cookie"))
                .andExpect(headerDoesNotExist("X-XSRF-TOKEN"))
                .andRespond(withSuccess("[{\"id\":\"1\"}]", MediaType.APPLICATION_JSON)
                        .header("Set-Cookie", "upstream=secret"));

        final var result = mockMvc.perform(get("/api/documents?page=1")
                        .header("Cookie", "other=1").header("X-XSRF-TOKEN", "browser-csrf")
                        .header("Authorization", "Bearer browser-supplied")
                        .with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isOk())
                .andExpect(content().json("[{\"id\":\"1\"}]"))
                .andReturn().getResponse();

        server.verify();
        assertFalse(result.getHeaders("Set-Cookie").stream().anyMatch(value -> value.contains("upstream")));
        assertNull(result.getHeader("Authorization"));
        assertFalse(result.getContentAsString().contains(ACCESS_TOKEN));
    }

    /**
     * Verifies that a state-changing call carrying the CSRF token is relayed with its method.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenDeleteHasCsrfToken_isRelayed() throws Exception {
        server.expect(requestTo(TARGET + "/api/documents/7"))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header("Authorization", "Bearer " + ACCESS_TOKEN))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        mockMvc.perform(delete("/api/documents/7").with(csrf()).with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isNoContent());

        server.verify();
    }

    /**
     * Verifies that a state-changing call without the CSRF token never reaches the resource server.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenDeleteLacksCsrfToken_isForbidden() throws Exception {
        server.expect(never(), requestTo(TARGET + "/api/documents/7")).andRespond(withStatus(HttpStatus.OK));

        mockMvc.perform(delete("/api/documents/7").with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isForbidden());

        server.verify();
    }

    /**
     * Verifies that an error of the resource server is returned unchanged.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenResourceServerFails_returnsItsStatus() throws Exception {
        server.expect(requestTo(TARGET + "/api/documents"))
                .andRespond(withStatus(HttpStatus.FORBIDDEN).body("denied"));

        mockMvc.perform(get("/api/documents").with(oidcLogin()).with(signedInClient()))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("WWW-Authenticate"))
                .andExpect(content().string("denied"));
    }

    /**
     * Verifies that an anonymous call gets a 401 and never reaches the resource server.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenCallerIsAnonymous_returnsUnauthorized() throws Exception {
        server.expect(never(), requestTo(TARGET + "/api/documents")).andRespond(withStatus(HttpStatus.OK));

        mockMvc.perform(get("/api/documents")).andExpect(status().isUnauthorized());

        server.verify();
    }

    /**
     * Verifies that a session whose user has no authorized client is answered with 401 and nothing is relayed.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void relay_whenSessionHasNoToken_returnsUnauthorized() throws Exception {
        server.expect(never(), requestTo(TARGET + "/api/documents")).andRespond(withStatus(HttpStatus.OK));

        final var result = mockMvc.perform(get("/api/documents").with(user("demo")))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();

        server.verify();
        assertEquals(HttpStatus.UNAUTHORIZED.value(), result.getStatus());
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
