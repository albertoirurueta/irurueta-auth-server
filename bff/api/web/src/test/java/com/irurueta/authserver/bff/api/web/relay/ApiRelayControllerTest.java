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
package com.irurueta.authserver.bff.api.web.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests of {@link ApiRelayController}. The REST client is a real one bound to a {@link MockRestServiceServer}.
 */
class ApiRelayControllerTest {

    /** Base URI of the resource server. */
    private static final String TARGET = "http://resource:9090";

    /** Server standing in for the resource server. */
    private MockRestServiceServer server;

    /** Controller under test. */
    private ApiRelayController controller;

    /**
     * Creates the controller over a REST client bound to the mock server.
     */
    @BeforeEach
    void setUp() {
        final var builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        controller = new ApiRelayController(builder.build(), new RelayProperties(URI.create(TARGET + "/")),
                new RelayHeaderFilter());
    }

    /**
     * Verifies that path, query and allowed headers are forwarded and the answer is streamed back without cookies.
     *
     * @throws IOException if the response cannot be written.
     */
    @Test
    void relay_whenGet_forwardsRequestAndStreamsResponse() throws IOException {
        server.expect(requestTo(TARGET + "/api/documents?page=1&q=a%20b"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/json"))
                .andExpect(headerDoesNotExist("Cookie"))
                .andExpect(headerDoesNotExist("X-XSRF-TOKEN"))
                .andExpect(headerDoesNotExist("X-CSRF-TOKEN"))
                .andRespond(withSuccess("[1]", MediaType.APPLICATION_JSON)
                        .header("Set-Cookie", "upstream=1").header("X-Total", "1"));
        final var request = new MockHttpServletRequest("GET", "/api/documents");
        request.setQueryString("page=1&q=a%20b");
        request.addHeader("Accept", "application/json");
        request.addHeader("Cookie", "__Host-SESSION=abc");
        request.addHeader("X-XSRF-TOKEN", "x");
        request.addHeader("X-CSRF-TOKEN", "y");
        final var response = new MockHttpServletResponse();

        controller.relay(request, response);

        server.verify();
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertEquals("[1]", response.getContentAsString());
        assertEquals("1", response.getHeader("X-Total"));
        assertNull(response.getHeader("Set-Cookie"));
    }

    /**
     * Verifies that the body of a state-changing request is forwarded.
     *
     * @throws IOException if the response cannot be written.
     */
    @Test
    void relay_whenPostHasBody_forwardsIt() throws IOException {
        server.expect(requestTo(TARGET + "/api/documents"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Content-Type", "application/json"))
                .andExpect(content().string("{\"a\":1}"))
                .andRespond(withStatus(HttpStatus.CREATED));
        final var request = new MockHttpServletRequest("POST", "/api/documents");
        request.setContentType("application/json");
        request.setContent("{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        final var response = new MockHttpServletResponse();

        controller.relay(request, response);

        server.verify();
        assertEquals(HttpStatus.CREATED.value(), response.getStatus());
    }

    /**
     * Verifies that a request announcing a chunked body is forwarded with a body.
     *
     * @throws IOException if the response cannot be written.
     */
    @Test
    void relay_whenBodyIsChunked_forwardsIt() throws IOException {
        server.expect(requestTo(TARGET + "/api/documents/7"))
                .andExpect(method(HttpMethod.PATCH))
                .andExpect(content().string(""))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));
        final var request = new MockHttpServletRequest("PATCH", "/api/documents/7");
        request.addHeader("Transfer-Encoding", "chunked");
        final var response = new MockHttpServletResponse();

        controller.relay(request, response);

        server.verify();
        assertEquals(HttpStatus.NO_CONTENT.value(), response.getStatus());
    }

    /**
     * Verifies that the context path is not part of the relayed path and that error statuses pass through unchanged.
     *
     * @throws IOException if the response cannot be written.
     */
    @Test
    void relay_whenUpstreamFailsAndContextPathIsSet_returnsItsStatusAndStripsContext() throws IOException {
        server.expect(requestTo(TARGET + "/api/documents/9"))
                .andExpect(method(HttpMethod.DELETE))
                .andRespond(withStatus(HttpStatus.NOT_FOUND).body("missing"));
        final var request = new MockHttpServletRequest("DELETE", "/bff-app/api/documents/9");
        request.setContextPath("/bff-app");
        final var response = new MockHttpServletResponse();

        controller.relay(request, response);

        server.verify();
        assertEquals(HttpStatus.NOT_FOUND.value(), response.getStatus());
        assertEquals("missing", response.getContentAsString());
    }

    /**
     * Verifies that a query that is not a valid URI is rejected with 400.
     */
    @Test
    void relay_whenQueryIsMalformed_throwsBadRequest() {
        final var request = new MockHttpServletRequest("GET", "/api/documents");
        request.setQueryString("q=a b");

        final var error = assertThrows(ResponseStatusException.class,
                () -> controller.relay(request, new MockHttpServletResponse()));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
    }

    /**
     * Verifies that a failure to obtain the token is answered with 401.
     */
    @Test
    void handleAuthorizationFailure_whenTokenIsUnavailable_returnsUnauthorized() {
        final var result = controller.handleAuthorizationFailure(
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant")));

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
    }

    /**
     * Verifies that an unreachable resource server is answered with 502.
     */
    @Test
    void handleUnreachableTarget_whenTargetIsDown_returnsBadGateway() {
        final var result = controller.handleUnreachableTarget(
                new ResourceAccessException("down", new IOException("refused")));

        assertEquals(HttpStatus.BAD_GATEWAY, result.getStatusCode());
    }
}
