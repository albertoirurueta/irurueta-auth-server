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
package com.irurueta.authserver.resourceserver;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.resourceserver.api.web.documents.DocumentController;
import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of the {@code opaque} profile: the resource server authenticates bearer tokens by calling an
 * introspection endpoint. The endpoint is a local HTTP server started by the test, whose answers the tests choose,
 * so no authorization server is needed. The client credentials the resource server presents are generated at
 * runtime and checked by the stub, never committed.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("opaque")
class OpaqueTokenSecurityIT {

    /** Subject the active introspection answers describe. */
    private static final String SUBJECT = "demo";

    /** Audience the resource server accepts. */
    private static final String ACCEPTED_AUDIENCE = "resource-server";

    /** Scope that allows reading documents. */
    private static final String READ_SCOPE = "documents.read";

    /** Scope that allows deleting documents. */
    private static final String DELETE_SCOPE = "documents.delete";

    /** HTTP status of a successful introspection. */
    private static final int HTTP_OK = 200;

    /** HTTP status of a rejected introspection client. */
    private static final int HTTP_UNAUTHORIZED = 401;

    /** Identifier the resource server presents to the introspection endpoint. */
    private static final String INTROSPECTION_CLIENT = "client-" + UUID.randomUUID();

    /** Credential the resource server presents to the introspection endpoint. */
    private static final String INTROSPECTION_CREDENTIAL = UUID.randomUUID() + "-" + UUID.randomUUID();

    /** Introspection answers by token value; a missing token is answered as inactive. */
    private static final Map<String, String> ANSWERS = new ConcurrentHashMap<>();

    /** Stub of the introspection endpoint. */
    private static final HttpServer INTROSPECTION = startIntrospectionServer();

    /** Store of the documents. */
    @Autowired
    private DocumentRepository documentRepository;

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Points the resource server at the stub introspection endpoint.
     *
     * @param registry registry of the test properties.
     */
    @DynamicPropertySource
    static void introspection(final DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri",
                () -> "http://127.0.0.1:" + INTROSPECTION.getAddress().getPort() + "/introspect");
        registry.add("spring.security.oauth2.resourceserver.opaquetoken.client-id", () -> INTROSPECTION_CLIENT);
        registry.add("spring.security.oauth2.resourceserver.opaquetoken.client-secret",
                () -> INTROSPECTION_CREDENTIAL);
    }

    /** Stops the stub introspection endpoint. */
    @AfterAll
    static void stopIntrospection() {
        INTROSPECTION.stop(0);
    }

    /**
     * Verifies that an active token with the accepted audience and the read scope lists the caller's documents.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenIntrospectionIsActiveWithReadScope_listsTheCallersDocuments() throws Exception {
        final var token = register(active(ACCEPTED_AUDIENCE, READ_SCOPE));
        documentRepository.save(new Document("opaque-own", SUBJECT, "Own", "text"));
        documentRepository.save(new Document("opaque-foreign", "someone-else", "Foreign", "text"));

        mockMvc.perform(get(DocumentController.PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == 'opaque-own')]").exists())
                .andExpect(jsonPath("$[?(@.id == 'opaque-foreign')]").doesNotExist());
    }

    /**
     * Verifies that an inactive token is answered with the {@code invalid_token} challenge.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenIntrospectionIsInactive_returnsUnauthorizedWithInvalidToken() throws Exception {
        final var token = register("{\"active\":false}");

        mockMvc.perform(get(DocumentController.PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    /**
     * Verifies that an active token issued to another audience is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenIntrospectionAudienceIsOther_returnsUnauthorized() throws Exception {
        final var token = register(active("bff", READ_SCOPE));

        mockMvc.perform(get(DocumentController.PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
    }

    /**
     * Verifies that an active token without the read scope is forbidden with {@code insufficient_scope}.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenIntrospectionLacksTheReadScope_returnsForbiddenWithInsufficientScope() throws Exception {
        final var token = register(active(ACCEPTED_AUDIENCE, "other"));

        mockMvc.perform(get(DocumentController.PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("insufficient_scope")));
    }

    /**
     * Verifies that a request without a bearer token is challenged.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenThereIsNoToken_returnsUnauthorizedWithBearerChallenge() throws Exception {
        mockMvc.perform(get(DocumentController.PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")));
    }

    /**
     * Verifies that deleting is denied to a token without the delete scope and allowed with it.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenDeleting_requiresTheDeleteScope() throws Exception {
        documentRepository.save(new Document("opaque-delete", SUBJECT, "Delete", "text"));
        final var reader = register(active(ACCEPTED_AUDIENCE, READ_SCOPE));
        final var deleter = register(strong(active(ACCEPTED_AUDIENCE, DELETE_SCOPE), Instant.now()));

        mockMvc.perform(delete(DocumentController.PATH + "/opaque-delete")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + reader))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("insufficient_scope")));
        mockMvc.perform(delete(DocumentController.PATH + "/opaque-delete")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + deleter))
                .andExpect(status().isNoContent());
        assertTrue(documentRepository.findByOwner(SUBJECT).stream()
                .noneMatch(document -> "opaque-delete".equals(document.id())));
    }

    /**
     * Verifies that an opaque token with the delete scope but the password-level {@code acr}, or a stale
     * {@code auth_time}, is answered with the RFC 9470 step-up challenge.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void documents_whenDeletingWithoutRecentStrongAuthentication_requiresStepUp() throws Exception {
        final var weak = register(active(ACCEPTED_AUDIENCE, DELETE_SCOPE));
        final var stale = register(strong(active(ACCEPTED_AUDIENCE, DELETE_SCOPE), Instant.now().minusSeconds(3600)));

        for (final var token : List.of(weak, stale)) {
            mockMvc.perform(delete(DocumentController.PATH + "/anything")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(
                            "error=\"insufficient_user_authentication\", acr_values=\"urn:irurueta:acr:mfa\", "
                                    + "max_age=\"300\"")));
        }
    }

    /**
     * Adds the strong {@code acr} and an {@code auth_time} to an introspection answer.
     *
     * @param answer   JSON answer.
     * @param authTime time the user authenticated.
     * @return the JSON answer.
     */
    private static String strong(final String answer, final Instant authTime) {
        return answer.substring(0, answer.length() - 1) + ",\"acr\":\"urn:irurueta:acr:mfa\",\"auth_time\":"
                + authTime.getEpochSecond() + "}";
    }

    /**
     * Registers the answer the stub gives for a new random token.
     *
     * @param answer JSON answer.
     * @return the token value.
     */
    private static String register(final String answer) {
        final var token = UUID.randomUUID().toString();
        ANSWERS.put(token, answer);
        return token;
    }

    /**
     * Builds an active introspection answer.
     *
     * @param audience audience of the token.
     * @param scope    scope of the token.
     * @return the JSON answer.
     */
    private static String active(final String audience, final String scope) {
        return "{\"active\":true,\"sub\":\"" + SUBJECT + "\",\"aud\":[\"" + audience + "\"],\"scope\":\"" + scope
                + "\",\"roles\":[\"ROLE_USER\"]}";
    }

    /**
     * Starts the stub introspection endpoint. It answers 401 unless the expected client credentials are presented.
     *
     * @return the started server.
     */
    private static HttpServer startIntrospectionServer() {
        try {
            final var server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            final var expected = "Basic " + Base64.getEncoder().encodeToString(
                    (INTROSPECTION_CLIENT + ":" + INTROSPECTION_CREDENTIAL).getBytes(StandardCharsets.UTF_8));
            server.createContext("/introspect", exchange -> {
                final var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                final var token = body.replaceFirst("^.*token=([^&]*).*$", "$1");
                final var authenticated = expected.equals(exchange.getRequestHeaders().getFirst("Authorization"));
                final var answer = authenticated
                        ? ANSWERS.getOrDefault(token, "{\"active\":false}") : "{\"error\":\"invalid_client\"}";
                final var bytes = answer.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(authenticated ? HTTP_OK : HTTP_UNAUTHORIZED, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            return server;
        } catch (final IOException e) {
            throw new IllegalStateException("The introspection stub cannot start", e);
        }
    }
}
