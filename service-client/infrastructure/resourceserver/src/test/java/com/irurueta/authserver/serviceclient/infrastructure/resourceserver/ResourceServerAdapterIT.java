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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentGateway;
import com.irurueta.authserver.serviceclient.domain.documents.OnBehalfOfDocumentGateway;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Integration test of the resource-server adapter against WireMock playing the token endpoint and the resource server:
 * the access token is requested with every authentication method, reused while it is valid and renewed inside the
 * refresh margin, exchanged with a subject and an actor token, and DPoP-bound when asked. The context is the adapter
 * alone (no Docker, no other module); keys are generated when the test runs.
 * <p>
 * Each nested class starts its own context, as each one configures the service client differently.
 */
class ResourceServerAdapterIT {

    /** Path of the fake token endpoint. */
    private static final String TOKEN_PATH = "/oauth2/token";

    /** Path of the fake documents endpoint. */
    private static final String DOCUMENTS_PATH = "/api/documents";

    /** Body the fake resource server answers. */
    private static final String DOCUMENTS_BODY = "[{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"Title\"}]";

    /** The documents of {@link #DOCUMENTS_BODY} in the domain. */
    private static final List<Document> DOCUMENTS = List.of(new Document("1", "alice", "Title"));

    /** Lifetime of a long-lived token, in seconds. */
    private static final int ONE_HOUR_SECONDS = 3600;

    /** Lifetime of a token that is inside the refresh margin, in seconds. */
    private static final int SHORT_LIVED_SECONDS = 30;

    /** HTTP status of a refused token. */
    private static final int FORBIDDEN = 403;

    /** HTTP status of a refused client. */
    private static final int UNAUTHORIZED = 401;

    /** Key pair of the {@code private_key_jwt} assertion, generated now. */
    private static final KeyPair KEY_PAIR = TestKeys.rsaKeyPair();

    /** Fake authorization server and resource server, on a random port, shared by the nested classes. */
    private static final WireMockServer WIRE_MOCK = new WireMockServer(WireMockConfiguration.options().dynamicPort());

    static {
        WIRE_MOCK.start();
    }

    /**
     * Only nested classes (which JUnit instantiates with it) and static helpers live here.
     */
    private ResourceServerAdapterIT() {
        // no instance is ever needed by hand
    }

    /**
     * Stops the fake servers.
     */
    @AfterAll
    static void stopWireMock() {
        WIRE_MOCK.stop();
    }

    /**
     * Points the service client at the fake servers.
     *
     * @param registry registry of the properties of the context.
     * @param method   authentication method.
     * @param dpop     whether tokens are DPoP-bound.
     */
    private static void configure(final DynamicPropertyRegistry registry, final String method, final boolean dpop) {
        registry.add("service-client.auth.method", () -> method);
        registry.add("service-client.auth.client-id", () -> "service-client");
        registry.add("service-client.auth.client-secret", () -> "s3cret");
        registry.add("service-client.auth.token-uri", () -> WIRE_MOCK.baseUrl() + TOKEN_PATH);
        registry.add("service-client.auth.dpop", () -> Boolean.toString(dpop));
        registry.add("service-client.auth.key.private-key", () -> TestKeys.pkcs8Pem(KEY_PAIR));
        registry.add("service-client.resource-server.base-uri", WIRE_MOCK::baseUrl);
    }

    /**
     * Makes the token endpoint answer a token for a grant.
     *
     * @param grantType grant type the request must carry.
     * @param token     value of the access token.
     * @param expiresIn lifetime of the token, in seconds.
     * @param type      token type.
     */
    private static void stubToken(final String grantType, final String token, final int expiresIn, final String type) {
        WIRE_MOCK.stubFor(post(urlEqualTo(TOKEN_PATH)).withRequestBody(containing("grant_type=" + grantType))
                .willReturn(aResponse().withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"" + token + "\",\"token_type\":\"" + type
                                + "\",\"expires_in\":" + expiresIn + ",\"scope\":\"documents.read\"}")));
    }

    /**
     * Makes the documents endpoint answer the documents to a request with an authorization header.
     *
     * @param authorization value the {@code Authorization} header must have.
     */
    private static void stubDocuments(final String authorization) {
        WIRE_MOCK.stubFor(get(urlEqualTo(DOCUMENTS_PATH)).withHeader("Authorization", equalTo(authorization))
                .willReturn(aResponse().withHeader("Content-Type", "application/json").withBody(DOCUMENTS_BODY)));
    }

    /**
     * Reads a form parameter of a request the token endpoint received.
     *
     * @param request the request.
     * @param name    name of the parameter.
     * @return the decoded value, or {@code null}.
     */
    private static String parameter(final LoggedRequest request, final String name) {
        for (final var pair : request.getBodyAsString().split("&")) {
            final var parts = pair.split("=", 2);
            if (parts[0].equals(name)) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /**
     * Context of the adapter alone: every class of the package, and Spring Boot's auto-configuration.
     */
    @SpringBootApplication
    static class TestApplication {
    }

    /**
     * Client credentials with a shared secret: the token is reused while valid. The context is discarded after each
     * test because it caches the access token: a token cached by one test would otherwise be reused by the next one,
     * which then would not request any.
     */
    @Nested
    @SpringBootTest(classes = TestApplication.class)
    @DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
    class ClientSecretBasic {

        /** Gateway under test. */
        @Autowired
        private DocumentGateway gateway;

        /**
         * Registers the properties.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            configure(registry, "client_secret_basic", false);
        }

        /**
         * Clears the fake servers.
         */
        @BeforeEach
        void reset() {
            WIRE_MOCK.resetAll();
        }

        /**
         * Verifies that two calls read the documents with the same token, requested once with Basic authentication.
         */
        @Test
        void listDocuments_whenTokenIsValid_reusesItAcrossCalls() {
            stubToken("client_credentials", "cc-token", ONE_HOUR_SECONDS, "Bearer");
            stubDocuments("Bearer cc-token");

            assertEquals(DOCUMENTS, gateway.listDocuments());
            assertEquals(DOCUMENTS, gateway.listDocuments());

            final var tokenRequests = WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH)));
            assertEquals(1, tokenRequests.size());
            assertNotNull(tokenRequests.getFirst().getHeader("Authorization"));
            assertTrue(tokenRequests.getFirst().getHeader("Authorization").startsWith("Basic "));
            WIRE_MOCK.verify(2, getRequestedFor(urlEqualTo(DOCUMENTS_PATH)));
        }

        /**
         * Verifies that a resource server that refuses the token is an access failure.
         */
        @Test
        void listDocuments_whenResourceServerRefusesTheToken_throwsDocumentAccessException() {
            stubToken("client_credentials", "cc-token", ONE_HOUR_SECONDS, "Bearer");
            WIRE_MOCK.stubFor(get(urlEqualTo(DOCUMENTS_PATH)).willReturn(aResponse().withStatus(FORBIDDEN)));

            assertThrows(DocumentAccessException.class, () -> gateway.listDocuments());
        }

        /**
         * Verifies that a token endpoint that refuses the client is an access failure.
         */
        @Test
        void listDocuments_whenTokenEndpointRefusesTheClient_throwsDocumentAccessException() {
            WIRE_MOCK.stubFor(post(urlEqualTo(TOKEN_PATH)).willReturn(aResponse().withStatus(UNAUTHORIZED)
                    .withHeader("Content-Type", "application/json").withBody("{\"error\":\"invalid_client\"}")));

            assertThrows(DocumentAccessException.class, () -> gateway.listDocuments());
        }
    }

    /**
     * Client credentials with a signed assertion.
     */
    @Nested
    @SpringBootTest(classes = TestApplication.class)
    class PrivateKeyJwt {

        /** Gateway under test. */
        @Autowired
        private DocumentGateway gateway;

        /**
         * Registers the properties.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            configure(registry, "private_key_jwt", false);
        }

        /**
         * Clears the fake servers.
         */
        @BeforeEach
        void reset() {
            WIRE_MOCK.resetAll();
        }

        /**
         * Verifies that the token request carries an assertion signed with the configured key and no secret.
         *
         * @throws Exception if the assertion cannot be parsed or verified.
         */
        @Test
        void listDocuments_whenMethodIsPrivateKeyJwt_sendsAnAssertionSignedWithTheConfiguredKey() throws Exception {
            stubToken("client_credentials", "cc-token", ONE_HOUR_SECONDS, "Bearer");
            stubDocuments("Bearer cc-token");

            assertEquals(DOCUMENTS, gateway.listDocuments());

            final var request = WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH))).getFirst();
            final var assertion = SignedJWT.parse(parameter(request, "client_assertion"));
            assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) KEY_PAIR.getPublic())));
            assertEquals("service-client", assertion.getJWTClaimsSet().getIssuer());
            assertEquals(null, parameter(request, "client_secret"));
        }
    }

    /**
     * Client credentials whose token is inside the refresh margin as soon as it is issued.
     */
    @Nested
    @SpringBootTest(classes = TestApplication.class, properties = "service-client.auth.refresh-before=PT60S")
    class Refresh {

        /** Gateway under test. */
        @Autowired
        private DocumentGateway gateway;

        /**
         * Registers the properties.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            configure(registry, "client_secret_basic", false);
        }

        /**
         * Clears the fake servers.
         */
        @BeforeEach
        void reset() {
            WIRE_MOCK.resetAll();
        }

        /**
         * Verifies that a token that expires within the margin is requested again by the next call.
         */
        @Test
        void listDocuments_whenTokenExpiresWithinTheMargin_requestsANewTokenEachCall() {
            stubToken("client_credentials", "short-lived", SHORT_LIVED_SECONDS, "Bearer");
            stubDocuments("Bearer short-lived");

            gateway.listDocuments();
            gateway.listDocuments();

            WIRE_MOCK.verify(2, postRequestedFor(urlEqualTo(TOKEN_PATH)));
        }
    }

    /**
     * Token exchange on behalf of a user.
     */
    @Nested
    @SpringBootTest(classes = TestApplication.class)
    class TokenExchange {

        /** Gateway under test. */
        @Autowired
        private OnBehalfOfDocumentGateway gateway;

        /**
         * Registers the properties.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            configure(registry, "client_secret_basic", false);
        }

        /**
         * Clears the fake servers.
         */
        @BeforeEach
        void reset() {
            WIRE_MOCK.resetAll();
        }

        /**
         * Verifies that the exchange sends the user's token as subject and the client's own token as actor, and that
         * the documents are read with the exchanged token.
         */
        @Test
        void listDocumentsAs_whenUserTokenIsGiven_exchangesItWithTheClientTokenAsActor() {
            stubToken("client_credentials", "cc-token", ONE_HOUR_SECONDS, "Bearer");
            stubToken("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange", "exchanged", ONE_HOUR_SECONDS,
                    "Bearer");
            stubDocuments("Bearer exchanged");

            assertEquals(DOCUMENTS, gateway.listDocumentsAs("user-token"));

            final var exchange = WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH))).stream()
                    .filter(request -> request.getBodyAsString().contains("token-exchange")
                            || request.getBodyAsString().contains("token%2Dexchange"))
                    .findFirst().orElseThrow();
            assertEquals("user-token", parameter(exchange, "subject_token"));
            assertEquals("cc-token", parameter(exchange, "actor_token"));
            WIRE_MOCK.verify(1, getRequestedFor(urlEqualTo(DOCUMENTS_PATH))
                    .withHeader("Authorization", equalTo("Bearer exchanged")));
        }
    }

    /**
     * DPoP-bound tokens.
     */
    @Nested
    @SpringBootTest(classes = TestApplication.class)
    class DPoP {

        /** Gateway under test. */
        @Autowired
        private DocumentGateway gateway;

        /**
         * Registers the properties.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            configure(registry, "client_secret_basic", true);
        }

        /**
         * Clears the fake servers.
         */
        @BeforeEach
        void reset() {
            WIRE_MOCK.resetAll();
        }

        /**
         * Verifies that the token request and the call both carry a proof and the call uses the DPoP scheme.
         *
         * @throws Exception if a proof cannot be parsed.
         */
        @Test
        void listDocuments_whenDPoPIsOn_sendsProofsAndTheDPoPScheme() throws Exception {
            stubToken("client_credentials", "dpop-token", ONE_HOUR_SECONDS, "DPoP");
            stubDocuments("DPoP dpop-token");

            assertEquals(DOCUMENTS, gateway.listDocuments());

            final var tokenRequest = WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH))).getFirst();
            final var tokenProof = SignedJWT.parse(tokenRequest.getHeader("DPoP")).getJWTClaimsSet();
            assertEquals("POST", tokenProof.getStringClaim("htm"));
            final var call = WIRE_MOCK.findAll(getRequestedFor(urlEqualTo(DOCUMENTS_PATH))).getFirst();
            final var callProof = SignedJWT.parse(call.getHeader("DPoP")).getJWTClaimsSet();
            assertEquals("GET", callProof.getStringClaim("htm"));
            assertNotNull(callProof.getStringClaim("ath"));
        }
    }
}
