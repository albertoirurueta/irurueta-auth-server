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


package com.irurueta.authserver.serviceclient;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentGateway;
import com.irurueta.authserver.serviceclient.domain.documents.OnBehalfOfDocumentGateway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Integration test of the service client application under each of its profiles. WireMock plays the authorization
 * server and the resource server; the runner of a profile executes while its context starts, so the fake servers are
 * stubbed before that, when the properties are registered. Each nested class starts its own context.
 */
class ServiceClientApplicationIT {

    /** Path of the fake token endpoint. */
    private static final String TOKEN_PATH = "/oauth2/token";

    /** Path of the fake documents endpoint. */
    private static final String DOCUMENTS_PATH = "/api/documents";

    /** Fake authorization server and resource server, on a random port, shared by the nested classes. */
    private static final WireMockServer WIRE_MOCK = new WireMockServer(WireMockConfiguration.options().dynamicPort());

    static {
        WIRE_MOCK.start();
    }

    /**
     * Only nested classes (which JUnit instantiates with it) and static helpers live here.
     */
    private ServiceClientApplicationIT() {
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
     * Stubs the fake servers (the token endpoint answers a token for any grant) and points the client at them.
     *
     * @param registry registry of the properties of the context.
     */
    private static void fakeServers(final DynamicPropertyRegistry registry) {
        WIRE_MOCK.resetAll();
        WIRE_MOCK.stubFor(post(urlEqualTo(TOKEN_PATH)).willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"access_token\":\"issued\",\"token_type\":\"Bearer\",\"expires_in\":300}")));
        WIRE_MOCK.stubFor(get(urlEqualTo(DOCUMENTS_PATH)).withHeader("Authorization", equalTo("Bearer issued"))
                .willReturn(aResponse().withHeader("Content-Type", "application/json")
                        .withBody("[{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"Title\"}]")));
        registry.add("service-client.auth.token-uri", () -> WIRE_MOCK.baseUrl() + TOKEN_PATH);
        registry.add("service-client.auth.client-secret", () -> "s3cret");
        registry.add("service-client.resource-server.base-uri", WIRE_MOCK::baseUrl);
    }

    /**
     * Default profile: the context starts with the gateways in place and no runner.
     */
    @Nested
    @SpringBootTest
    class DefaultProfile {

        /** The application context. */
        @Autowired
        private ApplicationContext context;

        /**
         * Verifies that both gateways exist and neither runner does.
         */
        @Test
        void contextLoads_whenNoProfileIsActive_providesTheGatewaysAndNoRunner() {
            assertNotNull(context.getBean(DocumentGateway.class));
            assertNotNull(context.getBean(OnBehalfOfDocumentGateway.class));
            assertThrows(NoSuchBeanDefinitionException.class, () -> context.getBean(ClientCredentialsCli.class));
            assertThrows(NoSuchBeanDefinitionException.class, () -> context.getBean(TokenExchangeCli.class));
        }
    }

    /**
     * {@code client-credentials} profile: the runner gets a token and reads the documents with it.
     */
    @Nested
    @SpringBootTest
    @ActiveProfiles(ClientCredentialsCli.PROFILE)
    class ClientCredentialsProfile {

        /** The application context. */
        @Autowired
        private ApplicationContext context;

        /**
         * Registers the properties and stubs the fake servers.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            fakeServers(registry);
        }

        /**
         * Verifies that the runner exists and one token was requested and used for the call.
         */
        @Test
        void contextLoads_whenProfileIsClientCredentials_runsTheRunnerWithATokenFromTheEndpoint() {
            assertNotNull(context.getBean(ClientCredentialsCli.class));
            assertEquals(1, WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH))).size());
            WIRE_MOCK.verify(1, getRequestedFor(urlEqualTo(DOCUMENTS_PATH))
                    .withHeader("Authorization", equalTo("Bearer issued")));
        }
    }

    /**
     * {@code token-exchange} profile: the runner exchanges the user's token and reads the documents with the result.
     */
    @Nested
    @SpringBootTest(properties = "service-client.cli.subject-token=user-token")
    @ActiveProfiles(TokenExchangeCli.PROFILE)
    class TokenExchangeProfile {

        /** The application context. */
        @Autowired
        private ApplicationContext context;

        /**
         * Registers the properties and stubs the fake servers.
         *
         * @param registry registry of the properties of the context.
         */
        @DynamicPropertySource
        static void properties(final DynamicPropertyRegistry registry) {
            fakeServers(registry);
        }

        /**
         * Verifies that the runner exists, that the token endpoint was asked for the client's own token and for the
         * exchange, and that the documents were read.
         */
        @Test
        void contextLoads_whenProfileIsTokenExchange_runsTheRunnerWithAnExchangedToken() {
            assertNotNull(context.getBean(TokenExchangeCli.class));
            assertEquals(2, WIRE_MOCK.findAll(postRequestedFor(urlEqualTo(TOKEN_PATH))).size());
            WIRE_MOCK.verify(1, getRequestedFor(urlEqualTo(DOCUMENTS_PATH)));
        }
    }
}
