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

import java.time.Clock;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Command-line client of the OAuth 2.0 device authorization grant (RFC 8628): requests a device code, prints the user
 * code and the verification URI, then polls the token endpoint honouring {@code interval}, {@code slow_down},
 * {@code authorization_pending} and {@code expired_token}.
 * <p>
 * <b>Running it from the packaged jar</b>: the class is a runner of the {@code device-flow} Spring profile, so
 * <pre>
 * java -jar service-client-boot.jar --spring.profiles.active=device-flow --device-flow.issuer=http://localhost:9000
 * </pre>
 * runs it instead of the regular application (which is unaffected without the profile). Optional settings are
 * {@code --device-flow.client-id}, {@code --device-flow.scope} and {@code --device-flow.print-access-token=true}.
 * <p>
 * <b>Output</b>, one line each and in this order, so a test can parse them:
 * <pre>
 * User code: ABCD-EFGH
 * Verification URI: http://localhost:9000/oauth2/device_verification
 * Verification URI (complete): http://localhost:9000/oauth2/device_verification?user_code=ABCD-EFGH
 * Device flow completed: token_type=Bearer expires_in=300 scope=profile documents.read refresh_token=false
 * </pre>
 * The tokens themselves are never printed unless {@code print-access-token} is set, which adds an
 * {@code Access token: ...} line. On any failure the process ends with a non-zero exit code.
 * <p>
 * <b>Why it lives in {@code src/main}</b>: the end-to-end test runs the packaged service-client jar, so the CLI has to
 * be in it; it is a genuine, reusable tool of the application and not a test double.
 */
@Slf4j
@Component
@Profile(DeviceFlowConfiguration.PROFILE)
@RequiredArgsConstructor
public class DeviceFlowCli implements CommandLineRunner {

    /**
     * Seconds added to the polling interval each time the server answers {@code slow_down} (RFC 8628 section 3.5).
     */
    public static final long SLOW_DOWN_INCREMENT_SECONDS = 5L;

    /** The expired token. */
    private static final String EXPIRED_TOKEN = "expired_token";

    /** The client. */
    private final DeviceAuthorizationClient client;

    /** The sleeper. */
    private final Sleeper sleeper;

    /** The clock. */
    private final Clock clock;

    /** The output. */
    private final DeviceFlowOutput output;

    /** The properties. */
    private final DeviceFlowProperties properties;

    /**
     * Runs the whole flow.
     *
     * @param args ignored: settings arrive as Spring properties.
     * @throws DeviceFlowException if the user denies the request, the device code expires, a request fails or the
     *                             thread is interrupted.
     */
    @Override
    public void run(final String... args) {
        final var authorization = client.requestDeviceAuthorization();
        output.line("User code: " + authorization.userCode());
        output.line("Verification URI: " + authorization.verificationUri());
        if (authorization.verificationUriComplete() != null) {
            output.line("Verification URI (complete): " + authorization.verificationUriComplete());
        }
        final var token = poll(authorization);
        output.line("Device flow completed: token_type=" + token.tokenType()
                + " expires_in=" + token.expiresIn()
                + " scope=" + token.scope()
                + " refresh_token=" + (token.refreshToken() != null));
        if (properties.printAccessToken()) {
            output.line("Access token: " + token.accessToken());
        }
    }

    /**
     * Polls until the user approves the request, the code expires or the server refuses.
     *
     * @param authorization the pending authorization.
     * @return the issued tokens.
     */
    private TokenResponse poll(final DeviceAuthorization authorization) {
        final var deadline = clock.instant().plusSeconds(authorization.expiresIn());
        var interval = authorization.interval();
        while (true) {
            pause(Duration.ofSeconds(interval));
            if (!clock.instant().isBefore(deadline)) {
                throw new DeviceFlowException("The device code expired before the request was approved");
            }
            final var outcome = client.pollToken(authorization.deviceCode());
            switch (outcome) {
                case PollOutcome.Granted granted -> {
                    return granted.token();
                }
                case PollOutcome.Pending ignored -> log.debug("Authorization pending");
                case PollOutcome.SlowDown ignored -> {
                    interval += SLOW_DOWN_INCREMENT_SECONDS;
                    log.info("The server asked to slow down, polling every {} seconds", interval);
                }
                case PollOutcome.Failed failed -> throw failure(failed);
            }
        }
    }

    /**
     * Waits, turning an interruption into a {@link DeviceFlowException}.
     *
     * @param duration how long to wait.
     */
    private void pause(final Duration duration) {
        try {
            sleeper.sleep(duration);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DeviceFlowException("Interrupted while waiting for the approval", e);
        }
    }

    /**
     * Maps a final error of the token endpoint to an exception.
     *
     * @param failed the error.
     * @return the exception to throw.
     */
    private DeviceFlowException failure(final PollOutcome.Failed failed) {
        if (EXPIRED_TOKEN.equals(failed.error())) {
            return new DeviceFlowException("The device code expired before the request was approved");
        }
        final var suffix = failed.description() == null ? "" : ": " + failed.description();
        return new DeviceFlowException("The device flow failed with " + failed.error() + suffix);
    }
}
