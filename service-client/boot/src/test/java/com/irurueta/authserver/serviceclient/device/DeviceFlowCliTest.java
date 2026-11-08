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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeviceFlowCli}: the poll loop runs against mocks, with no sleeping and no network.
 */
@ExtendWith(MockitoExtension.class)
class DeviceFlowCliTest {

    /** The start. */
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** The interval. */
    private static final long INTERVAL = 5L;

    /** Number of polls of the slow-down scenario. */
    private static final long POLLS = 3L;

    /** The expires in. */
    private static final long EXPIRES_IN = 300L;

    /** The token expires in. */
    private static final long TOKEN_EXPIRES_IN = 3600L;

    /** The device code. */
    private static final String DEVICE_CODE = "device-code";

    /** The user code. */
    private static final String USER_CODE = "ABCD-EFGH";

    /** The verification uri. */
    private static final String VERIFICATION_URI = "http://auth.test/oauth2/device_verification";

    /** The complete uri. */
    private static final String COMPLETE_URI = VERIFICATION_URI + "?user_code=" + USER_CODE;

    /** The access token. */
    private static final String ACCESS_TOKEN = "the-access-token";

    /**
     * Server side of the flow.
     */
    @Mock
    private DeviceAuthorizationClient client;

    /**
     * Wait between polls.
     */
    @Mock
    private Sleeper sleeper;

    /**
     * Time source.
     */
    @Mock
    private Clock clock;

    /**
     * Where the lines go.
     */
    @Mock
    private DeviceFlowOutput output;

    /**
     * CLI settings.
     */
    @Mock
    private DeviceFlowProperties properties;

    /**
     * Subject under test.
     */
    @InjectMocks
    private DeviceFlowCli cli;

    /**
     * Pending answers are retried after the same interval until the tokens arrive.
     *
     * @throws InterruptedException never: the sleeper is a mock.
     */
    @Test
    void run_whenApprovedAfterPending_printsLinesAndWaitsTheInterval() throws InterruptedException {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL), START.plusSeconds(2 * INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Pending(), new PollOutcome.Granted(token()));

        cli.run();

        final var order = inOrder(output, sleeper);
        order.verify(output).line("User code: " + USER_CODE);
        order.verify(output).line("Verification URI: " + VERIFICATION_URI);
        order.verify(output).line("Verification URI (complete): " + COMPLETE_URI);
        order.verify(sleeper, times(2)).sleep(Duration.ofSeconds(INTERVAL));
        order.verify(output).line("Device flow completed: token_type=Bearer expires_in=" + TOKEN_EXPIRES_IN
                + " scope=profile documents.read refresh_token=true");
        verify(output, never()).line("Access token: " + ACCESS_TOKEN);
    }

    /**
     * Every {@code slow_down} makes the interval five seconds longer.
     *
     * @throws InterruptedException never: the sleeper is a mock.
     */
    @Test
    void run_whenServerSaysSlowDown_increasesTheInterval() throws InterruptedException {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL), START.plusSeconds(2 * INTERVAL),
                START.plusSeconds(POLLS * INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.SlowDown(), new PollOutcome.SlowDown(),
                new PollOutcome.Granted(token()));

        cli.run();

        final var order = inOrder(sleeper);
        order.verify(sleeper).sleep(Duration.ofSeconds(INTERVAL));
        order.verify(sleeper).sleep(Duration.ofSeconds(INTERVAL + DeviceFlowCli.SLOW_DOWN_INCREMENT_SECONDS));
        order.verify(sleeper).sleep(Duration.ofSeconds(INTERVAL + 2 * DeviceFlowCli.SLOW_DOWN_INCREMENT_SECONDS));
    }

    /**
     * The verification URI with the code is optional.
     */
    @Test
    void run_whenNoCompleteUri_doesNotPrintIt() {
        stubAuthorization(null, START, START.plusSeconds(INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Granted(token()));

        cli.run();

        verify(output, never()).line(startsWith("Verification URI (complete)"));
    }

    /**
     * The access token is printed only when the settings ask for it.
     */
    @Test
    void run_whenPrintAccessTokenIsSet_printsTheAccessToken() {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Granted(token()));
        when(properties.printAccessToken()).thenReturn(true);

        cli.run();

        verify(output).line("Access token: " + ACCESS_TOKEN);
    }

    /**
     * Once the deadline passes the token endpoint is not called any more.
     */
    @Test
    void run_whenDeadlinePasses_throwsWithoutPolling() {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(EXPIRES_IN));

        final var error = assertThrows(DeviceFlowException.class, () -> cli.run());

        assertTrue(error.getMessage().contains("expired"));
        verify(client, never()).pollToken(anyString());
    }

    /**
     * An {@code expired_token} answer ends the flow.
     */
    @Test
    void run_whenServerSaysExpiredToken_throwsExpired() {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Failed("expired_token", null));

        final var error = assertThrows(DeviceFlowException.class, () -> cli.run());

        assertTrue(error.getMessage().contains("expired"));
    }

    /**
     * Any other error names the error code and its description.
     */
    @Test
    void run_whenAccessDeniedWithDescription_throwsWithCodeAndDescription() {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Failed("access_denied", "no way"));

        final var error = assertThrows(DeviceFlowException.class, () -> cli.run());

        assertTrue(error.getMessage().contains("access_denied: no way"));
    }

    /**
     * An error without description is named by its code alone.
     */
    @Test
    void run_whenFailureHasNoDescription_throwsWithCodeOnly() {
        stubAuthorization(COMPLETE_URI, START, START.plusSeconds(INTERVAL));
        when(client.pollToken(DEVICE_CODE)).thenReturn(new PollOutcome.Failed("access_denied", null));

        final var error = assertThrows(DeviceFlowException.class, () -> cli.run());

        assertTrue(error.getMessage().endsWith("access_denied"));
    }

    /**
     * An interruption stops the flow and keeps the interrupt flag.
     *
     * @throws InterruptedException never: the sleeper is a mock.
     */
    @Test
    void run_whenInterrupted_throwsAndRestoresTheInterruptFlag() throws InterruptedException {
        stubAuthorization(COMPLETE_URI, START);
        doThrow(new InterruptedException("stop")).when(sleeper).sleep(Duration.ofSeconds(INTERVAL));

        try {
            assertThrows(DeviceFlowException.class, () -> cli.run());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            assertTrue(Thread.interrupted());
        }
        assertFalse(Thread.currentThread().isInterrupted());
    }

    /**
     * A failing device authorization request ends the flow before anything is printed.
     */
    @Test
    void run_whenAuthorizationRequestFails_propagatesTheException() {
        final var failure = new DeviceFlowException("down");
        when(client.requestDeviceAuthorization()).thenThrow(failure);

        final var error = assertThrows(DeviceFlowException.class, () -> cli.run());

        assertSame(failure, error);
        verify(output, never()).line(anyString());
    }

    /**
     * Stubs the device authorization and the successive readings of the clock.
     *
     * @param completeUri the complete verification URI, or {@code null}.
     * @param first       the first reading, taken to compute the deadline.
     * @param others      the following readings, one per poll.
     */
    private void stubAuthorization(final String completeUri, final Instant first, final Instant... others) {
        when(client.requestDeviceAuthorization()).thenReturn(new DeviceAuthorization(DEVICE_CODE, USER_CODE,
                VERIFICATION_URI, completeUri, EXPIRES_IN, INTERVAL));
        when(clock.instant()).thenReturn(first, others);
    }

    /**
     * Builds a token response.
     *
     * @return the tokens.
     */
    private static TokenResponse token() {
        return new TokenResponse(ACCESS_TOKEN, "the-refresh-token", "Bearer", TOKEN_EXPIRES_IN,
                "profile documents.read");
    }
}
