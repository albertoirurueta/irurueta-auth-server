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

package com.irurueta.authserver.serviceclient.device;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Unit tests of {@link DeviceAuthorizationClient} against a {@link MockRestServiceServer}: no real network.
 */
class DeviceAuthorizationClientTest {

    /** The base url. */
    private static final String BASE_URL = "http://auth.test";

    /** The expires in. */
    private static final long EXPIRES_IN = 600L;

    /** The interval. */
    private static final long INTERVAL = 7L;

    /** The token expires in. */
    private static final long TOKEN_EXPIRES_IN = 300L;

    /** The server. */
    private MockRestServiceServer server;

    /** The client. */
    private DeviceAuthorizationClient client;

    /**
     * Binds a client with the default settings to a mock server.
     */
    @BeforeEach
    void setUp() {
        final var builder = RestClient.builder().baseUrl(BASE_URL);
        server = MockRestServiceServer.bindTo(builder).build();
        client = new DeviceAuthorizationClient(builder.build(),
                new DeviceFlowProperties(URI.create(BASE_URL), null, null, false));
    }

    /**
     * The request carries the client id and the scope as a form, and the answer is mapped.
     */
    @Test
    void requestDeviceAuthorization_whenServerAnswers_postsFormAndMapsResponse() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.DEVICE_AUTHORIZATION_PATH))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Content-Type", containsString("application/x-www-form-urlencoded")))
                .andExpect(content().string(containsString("client_id=device-client")))
                .andExpect(content().string(containsString("scope=profile+documents.read")))
                .andRespond(withSuccess("{\"device_code\":\"dc\",\"user_code\":\"UC\","
                        + "\"verification_uri\":\"http://auth.test/v\","
                        + "\"verification_uri_complete\":\"http://auth.test/v?user_code=UC\","
                        + "\"expires_in\":600,\"interval\":7,\"extra\":true}", MediaType.APPLICATION_JSON));

        final var result = client.requestDeviceAuthorization();

        assertEquals(new DeviceAuthorization("dc", "UC", "http://auth.test/v", "http://auth.test/v?user_code=UC",
                EXPIRES_IN, INTERVAL), result);
        server.verify();
    }

    /**
     * A {@code null} interval or lifetime, which is what the Spring Authorization Server's answer carries for a member
     * it does not set, is mapped to the defaults instead of failing to parse.
     */
    @Test
    void requestDeviceAuthorization_whenIntervalAndLifetimeAreNull_usesTheDefaults() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.DEVICE_AUTHORIZATION_PATH))
                .andRespond(withSuccess("{\"device_code\":\"dc\",\"user_code\":\"UC\","
                        + "\"verification_uri\":\"http://auth.test/v\",\"expires_in\":null,\"interval\":null}",
                        MediaType.APPLICATION_JSON));

        final var result = client.requestDeviceAuthorization();

        assertEquals(DeviceAuthorization.DEFAULT_EXPIRES_IN_SECONDS, result.expiresIn());
        assertEquals(DeviceAuthorization.DEFAULT_INTERVAL_SECONDS, result.interval());
        server.verify();
    }

    /**
     * An HTTP error is a {@link DeviceFlowException}.
     */
    @Test
    void requestDeviceAuthorization_whenServerFails_throwsDeviceFlowException() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.DEVICE_AUTHORIZATION_PATH))
                .andRespond(withServerError());

        final var error = assertThrows(DeviceFlowException.class, () -> client.requestDeviceAuthorization());

        assertTrue(error.getMessage().startsWith("The device authorization request failed"));
    }

    /**
     * An empty answer is refused.
     */
    @Test
    void requestDeviceAuthorization_whenBodyIsEmpty_throwsDeviceFlowException() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.DEVICE_AUTHORIZATION_PATH))
                .andRespond(withStatus(HttpStatus.OK));

        assertThrows(DeviceFlowException.class, () -> client.requestDeviceAuthorization());
    }

    /**
     * A successful poll yields the tokens.
     */
    @Test
    void pollToken_whenApproved_returnsGrantedAndSendsTheDeviceCodeGrant() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString(
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")))
                .andExpect(content().string(containsString("device_code=dc")))
                .andExpect(content().string(containsString("client_id=device-client")))
                .andRespond(withSuccess("{\"access_token\":\"at\",\"token_type\":\"Bearer\","
                        + "\"expires_in\":300,\"scope\":\"profile\"}", MediaType.APPLICATION_JSON));

        final var outcome = assertInstanceOf(PollOutcome.Granted.class, client.pollToken("dc"));

        assertEquals(new TokenResponse("at", null, "Bearer", TOKEN_EXPIRES_IN, "profile"), outcome.token());
        server.verify();
    }

    /**
     * A successful status with no body is not a grant.
     */
    @Test
    void pollToken_whenSuccessBodyIsEmpty_returnsFailed() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(withStatus(HttpStatus.OK));

        final var outcome = assertInstanceOf(PollOutcome.Failed.class, client.pollToken("dc"));

        assertEquals("invalid_response", outcome.error());
    }

    /**
     * {@code authorization_pending} is mapped.
     */
    @Test
    void pollToken_whenAuthorizationPending_returnsPending() {
        respondWithError("authorization_pending");

        assertInstanceOf(PollOutcome.Pending.class, client.pollToken("dc"));
    }

    /**
     * {@code slow_down} is mapped.
     */
    @Test
    void pollToken_whenSlowDown_returnsSlowDown() {
        respondWithError("slow_down");

        assertInstanceOf(PollOutcome.SlowDown.class, client.pollToken("dc"));
    }

    /**
     * Other errors keep their code and description.
     */
    @Test
    void pollToken_whenExpiredToken_returnsFailedWithCode() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(withBadRequest().contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"expired_token\",\"error_description\":\"too late\"}"));

        final var outcome = assertInstanceOf(PollOutcome.Failed.class, client.pollToken("dc"));

        assertEquals("expired_token", outcome.error());
        assertEquals("too late", outcome.description());
    }

    /**
     * An error answer without {@code error} is reported as an invalid response.
     */
    @Test
    void pollToken_whenErrorBodyHasNoCode_returnsInvalidResponse() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(withBadRequest().contentType(MediaType.APPLICATION_JSON).body("{}"));

        final var outcome = assertInstanceOf(PollOutcome.Failed.class, client.pollToken("dc"));

        assertEquals("invalid_response", outcome.error());
    }

    /**
     * An error answer with no body at all is reported as an invalid response.
     */
    @Test
    void pollToken_whenErrorBodyIsEmpty_returnsInvalidResponse() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(withBadRequest());

        final var outcome = assertInstanceOf(PollOutcome.Failed.class, client.pollToken("dc"));

        assertEquals("invalid_response", outcome.error());
    }

    /**
     * A transport failure is a {@link DeviceFlowException}.
     */
    @Test
    void pollToken_whenConnectionFails_throwsDeviceFlowException() {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(request -> {
                    throw new IOException("refused");
                });

        final var error = assertThrows(DeviceFlowException.class, () -> client.pollToken("dc"));

        assertTrue(error.getMessage().startsWith("The token request failed"));
    }

    /**
     * Makes the mock server answer a token request with an OAuth error.
     *
     * @param code the error code.
     */
    private void respondWithError(final String code) {
        server.expect(requestTo(BASE_URL + DeviceAuthorizationClient.TOKEN_PATH))
                .andRespond(withBadRequest().contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"" + code + "\"}"));
    }
}
