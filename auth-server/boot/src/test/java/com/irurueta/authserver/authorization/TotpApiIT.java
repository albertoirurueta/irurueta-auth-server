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

package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Checks the authenticator app, recovery code and trusted device endpoints of the account API against the real
 * application. The requests carry a {@code jwt()} for the owner of the account, so the tests do not depend on the
 * token endpoint; removing or resetting the second factor of an account that has one also needs the {@code acr} and
 * {@code auth_time} of a recent multi-factor sign-in. Every test creates its own users.
 */
@PostgresIT
@AutoConfigureMockMvc
class TotpApiIT {

    /** Path of the authenticator app endpoint. */
    private static final String TOTP_PATH = "/api/account/totp";

    /** Path of the confirmation endpoint. */
    private static final String CONFIRM_PATH = TOTP_PATH + "/confirm";

    /** Path of the recovery codes endpoint. */
    private static final String RECOVERY_PATH = "/api/account/recovery-codes";

    /** Path of the trusted devices endpoint. */
    private static final String DEVICES_PATH = "/api/account/trusted-devices";

    /** Prefix of the QR code data URI. */
    private static final String QR_PREFIX = "data:image/png;base64,";

    /** A code that is not six digits. */
    private static final String MALFORMED_CODE = "12ab";

    /** The RFC 9470 challenge of an operation that needs a recent multi-factor sign-in. */
    private static final String STEP_UP_CHALLENGE = "Bearer error=\"insufficient_user_authentication\", "
            + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\"";

    /** Seconds since a multi-factor sign-in that is too old for a step-up (the default maximum is five minutes). */
    private static final long OLD_SIGN_IN_SECONDS = 600;

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Port that stores the authenticator app credentials. */
    @Autowired
    private TotpCredentialRepository totpCredentials;

    /** Port that stores the recovery codes. */
    @Autowired
    private RecoveryCodeRepository recoveryCodes;

    /** Port that stores the trusted devices. */
    @Autowired
    private TrustedDeviceRepository trustedDevices;

    /** Decrypts the stored secrets, so the tests can compute a valid code. */
    @Autowired
    private TotpSecretCipher totpSecretCipher;

    /** The TOTP algorithm of the application. */
    @Autowired
    private TotpAlgorithm totpAlgorithm;

    /** Use case that trusts a device. */
    @Autowired
    private CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that an enrolment answers the {@code otpauth} URI and a PNG QR code, and stores a pending credential.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void enrollTotp_whenAccountIsAuthenticated_answersUriAndQrCode() throws Exception {
        final var user = fixtures.createUser();

        mockMvc.perform(post(TOTP_PATH).with(bearerOf(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.otpauthUri").value(startsWith("otpauth://totp/")))
                .andExpect(jsonPath("$.qrCode").value(startsWith(QR_PREFIX)));

        assertFalse(totpCredentials.findByUser(idOf(user)).orElseThrow().confirmed());
    }

    /**
     * Verifies that the endpoints need a bearer token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void enrollTotp_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(post(TOTP_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(CONFIRM_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(delete(TOTP_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(RECOVERY_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(get(DEVICES_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(delete(DEVICES_PATH + "/" + UUID.randomUUID())).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a confirmed authenticator app cannot be enrolled again.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void enrollTotp_whenAlreadyEnabled_returnsConflict() throws Exception {
        final var user = fixtures.createUser();
        enableTotp(user);

        mockMvc.perform(post(TOTP_PATH).with(bearerOf(user)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:totp-already-enabled"));
    }

    /**
     * Verifies that a right code enables the factor and answers ten recovery codes, once.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void confirmTotp_whenCodeIsRight_enablesTheFactorAndAnswersRecoveryCodes() throws Exception {
        final var user = fixtures.createUser();
        mockMvc.perform(post(TOTP_PATH).with(bearerOf(user))).andExpect(status().isOk());

        mockMvc.perform(post(CONFIRM_PATH).with(bearerOf(user)).contentType(MediaType.APPLICATION_JSON)
                        .content(codeBody(currentCode(user))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.remaining").value(GenerateRecoveryCodesUseCase.CODE_COUNT))
                .andExpect(jsonPath("$.recoveryCodes.length()").value(GenerateRecoveryCodesUseCase.CODE_COUNT));

        assertTrue(totpCredentials.findByUser(idOf(user)).orElseThrow().confirmed());
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, recoveryCodes.findUnused(idOf(user)).size());
    }

    /**
     * Verifies that a code that is not six digits is rejected by the contract's validation.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void confirmTotp_whenCodeIsMalformed_returnsBadRequest() throws Exception {
        final var user = fixtures.createUser();

        mockMvc.perform(post(CONFIRM_PATH).with(bearerOf(user)).contentType(MediaType.APPLICATION_JSON)
                        .content(codeBody(MALFORMED_CODE)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Verifies that a confirmation without an enrolment is a bad request.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void confirmTotp_whenNothingWasEnrolled_returnsBadRequest() throws Exception {
        final var user = fixtures.createUser();

        mockMvc.perform(post(CONFIRM_PATH).with(bearerOf(user)).contentType(MediaType.APPLICATION_JSON)
                        .content(codeBody("123456")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:totp-not-enrolled"));
    }

    /**
     * Verifies that a wrong code is a bad request and leaves the enrolment pending.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void confirmTotp_whenCodeIsWrong_returnsBadRequestAndStaysPending() throws Exception {
        final var user = fixtures.createUser();
        mockMvc.perform(post(TOTP_PATH).with(bearerOf(user))).andExpect(status().isOk());

        mockMvc.perform(post(CONFIRM_PATH).with(bearerOf(user)).contentType(MediaType.APPLICATION_JSON)
                        .content(codeBody(codeOutsideTheWindow(user))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:invalid-code"));

        assertFalse(totpCredentials.findByUser(idOf(user)).orElseThrow().confirmed());
    }

    /**
     * Verifies that disabling, with a recent multi-factor sign-in, removes the credential, the recovery codes and
     * every trusted device, and that it only touches the caller's own account.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void disableTotp_whenEnabled_removesTheFactorAndTheTrustedDevicesOfTheCallerOnly() throws Exception {
        final var user = fixtures.createUser();
        final var other = fixtures.createUser();
        enableTotp(user);
        enableTotp(other);
        trust(user, "Firefox on Linux");
        trust(user, "Safari on macOS");
        trust(other, "Safari on macOS");

        mockMvc.perform(delete(TOTP_PATH).with(stepUpBearerOf(user)))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

        assertTrue(totpCredentials.findByUser(idOf(user)).isEmpty());
        assertTrue(recoveryCodes.findUnused(idOf(user)).isEmpty());
        assertTrue(trustedDevices.findByUser(idOf(user), Instant.now()).isEmpty());
        assertTrue(totpCredentials.findByUser(idOf(other)).orElseThrow().confirmed());
        assertEquals(1, trustedDevices.findByUser(idOf(other), Instant.now()).size());
    }

    // tag::mfa-step-up-api-it[]
    /**
     * Verifies that removing or resetting the second factor of an account that has one needs a recent multi-factor
     * sign-in: a password-only token and an old multi-factor one are answered with {@code 401} and the RFC 9470
     * challenge, and nothing is removed.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void disableTotp_whenTokenShowsNoRecentMultiFactorSignIn_answersTheStepUpChallenge() throws Exception {
        final var user = fixtures.createUser();
        enableTotp(user);
        final var device = trust(user, "Firefox on Linux");
        final var old = jwt().jwt(token -> token.subject(user.username())
                .claim("acr", AuthenticationContextClass.MULTI_FACTOR)
                .claim("auth_time", Instant.now().minusSeconds(OLD_SIGN_IN_SECONDS).getEpochSecond()));

        for (final var token : List.<RequestPostProcessor>of(bearerOf(user), old)) {
            mockMvc.perform(delete(TOTP_PATH).with(token))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE))
                    .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));
        }
        mockMvc.perform(post(RECOVERY_PATH).with(bearerOf(user)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE));
        mockMvc.perform(delete(DEVICES_PATH + "/" + device).with(bearerOf(user)))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", STEP_UP_CHALLENGE));

        assertTrue(totpCredentials.findByUser(idOf(user)).orElseThrow().confirmed());
        assertEquals(1, trustedDevices.findByUser(idOf(user), Instant.now()).size());
    }
    // end::mfa-step-up-api-it[]

    /**
     * Verifies that a device of an account with a second factor is revoked with a recent multi-factor sign-in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revokeTrustedDevice_whenAccountHasASecondFactorAndSteppedUp_removesIt() throws Exception {
        final var user = fixtures.createUser();
        enableTotp(user);
        final var id = trust(user, "Firefox on Linux");

        mockMvc.perform(delete(DEVICES_PATH + "/" + id).with(stepUpBearerOf(user))).andExpect(status().isNoContent());

        assertTrue(trustedDevices.findByUser(idOf(user), Instant.now()).isEmpty());
    }

    /**
     * Verifies that new recovery codes replace the old set.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generateRecoveryCodes_whenCalled_replacesTheSet() throws Exception {
        final var user = fixtures.createUser();
        enableTotp(user);
        final var before = recoveryCodes.findUnused(idOf(user));

        mockMvc.perform(post(RECOVERY_PATH).with(stepUpBearerOf(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.remaining").value(GenerateRecoveryCodesUseCase.CODE_COUNT))
                .andExpect(jsonPath("$.recoveryCodes.length()").value(GenerateRecoveryCodesUseCase.CODE_COUNT));

        final var after = recoveryCodes.findUnused(idOf(user));
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, after.size());
        assertTrue(after.stream().noneMatch(code -> before.stream().anyMatch(old -> old.id().equals(code.id()))));
    }

    /**
     * Verifies that recovery codes are refused to an account without a confirmed second factor, and none is stored.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void generateRecoveryCodes_whenNoSecondFactorIsConfirmed_returnsBadRequest() throws Exception {
        final var user = fixtures.createUser();

        mockMvc.perform(post(RECOVERY_PATH).with(bearerOf(user)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:totp-not-enrolled"));

        assertTrue(recoveryCodes.findUnused(idOf(user)).isEmpty());
    }

    /**
     * Verifies that the list holds the caller's devices and never another account's.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void listTrustedDevices_whenBothAccountsHaveDevices_listsOnlyTheCallers() throws Exception {
        final var user = fixtures.createUser();
        final var other = fixtures.createUser();
        final var own = trust(user, "Firefox on Linux");
        trust(other, "Safari on macOS");

        mockMvc.perform(get(DEVICES_PATH).with(bearerOf(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(own.toString()))
                .andExpect(jsonPath("$[0].userAgentSummary").value("Firefox on Linux"))
                .andExpect(jsonPath("$[0].hashedToken").doesNotExist());
    }

    /**
     * Verifies that a device is revoked by its owner.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revokeTrustedDevice_whenOwnerRevokes_removesIt() throws Exception {
        final var user = fixtures.createUser();
        final var id = trust(user, "Firefox on Linux");

        mockMvc.perform(delete(DEVICES_PATH + "/" + id).with(bearerOf(user))).andExpect(status().isNoContent());

        mockMvc.perform(get(DEVICES_PATH).with(bearerOf(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    /**
     * Verifies that the device of another account, and one that does not exist, are answered as not found and the
     * device of the other account survives.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revokeTrustedDevice_whenDeviceBelongsToAnotherAccount_returnsNotFoundAndKeepsIt() throws Exception {
        final var user = fixtures.createUser();
        final var other = fixtures.createUser();
        final var foreign = trust(other, "Safari on macOS");

        mockMvc.perform(delete(DEVICES_PATH + "/" + foreign).with(bearerOf(user)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:trusted-device-not-found"));
        mockMvc.perform(delete(DEVICES_PATH + "/" + UUID.randomUUID()).with(bearerOf(user)))
                .andExpect(status().isNotFound());

        assertEquals(1, trustedDevices.findByUser(idOf(other), Instant.now()).size());
    }

    /**
     * Verifies that a device identifier that is not a UUID is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revokeTrustedDevice_whenIdIsNotAUuid_returnsBadRequest() throws Exception {
        final var user = fixtures.createUser();

        mockMvc.perform(delete(DEVICES_PATH + "/not-a-uuid").with(bearerOf(user)))
                .andExpect(status().isBadRequest());
    }

    /**
     * Builds the bearer token of a user.
     *
     * @param user the user, the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor bearerOf(final AuthServerFixtures.TestUser user) {
        return jwt().jwt(token -> token.subject(user.username()));
    }

    /**
     * Builds the bearer token of a user who signed in with a second factor just now.
     *
     * @param user the user, the subject of the token.
     * @return the request post-processor.
     */
    private static RequestPostProcessor stepUpBearerOf(final AuthServerFixtures.TestUser user) {
        return jwt().jwt(token -> token.subject(user.username())
                .claim("acr", AuthenticationContextClass.MULTI_FACTOR)
                .claim("auth_time", Instant.now().getEpochSecond()));
    }

    /**
     * Gets the identifier of a user.
     *
     * @param user the user.
     * @return its account identifier.
     */
    private UUID idOf(final AuthServerFixtures.TestUser user) {
        return userAccounts.findByUsername(user.username()).orElseThrow().id();
    }

    /**
     * Enrols and confirms the authenticator app of a user.
     *
     * @param user the user.
     * @throws Exception if a request cannot be performed.
     */
    private void enableTotp(final AuthServerFixtures.TestUser user) throws Exception {
        mockMvc.perform(post(TOTP_PATH).with(bearerOf(user))).andExpect(status().isOk());
        mockMvc.perform(post(CONFIRM_PATH).with(bearerOf(user)).contentType(MediaType.APPLICATION_JSON)
                .content(codeBody(currentCode(user)))).andExpect(status().isOk());
    }

    /**
     * Trusts a device of a user.
     *
     * @param user    the user.
     * @param summary summary of its browser.
     * @return the identifier of the device.
     */
    private UUID trust(final AuthServerFixtures.TestUser user, final String summary) {
        return createTrustedDeviceUseCase.execute(idOf(user), user.username(), summary).device().id();
    }

    /**
     * Computes the code the authenticator app of a user shows now.
     *
     * @param user the user, with a pending enrolment.
     * @return the six-digit code.
     */
    private String currentCode(final AuthServerFixtures.TestUser user) {
        return codeAt(user, totpAlgorithm.stepAt(Instant.now()));
    }

    /**
     * Computes the code of a step.
     *
     * @param user the user, with a pending enrolment.
     * @param step the time step.
     * @return the six-digit code.
     */
    private String codeAt(final AuthServerFixtures.TestUser user, final long step) {
        final var secret = totpSecretCipher.decrypt(totpCredentials.findByUser(idOf(user)).orElseThrow()
                .encryptedSecret());
        return totpAlgorithm.generate(secret, step);
    }

    /**
     * Finds a six-digit code the algorithm does not accept now, whatever the clock skew window.
     *
     * @param user the user, with a pending enrolment.
     * @return a code that matches none of the accepted steps.
     */
    private String codeOutsideTheWindow(final AuthServerFixtures.TestUser user) {
        final var now = totpAlgorithm.stepAt(Instant.now());
        final var accepted = LongStream.rangeClosed(now - TotpAlgorithm.WINDOW - 1, now + TotpAlgorithm.WINDOW + 1)
                .mapToObj(step -> codeAt(user, step)).toList();
        return IntStream.iterate(0, i -> i + 1)
                .mapToObj(i -> String.format(Locale.ROOT, "%0" + TotpAlgorithm.DIGITS + "d", i))
                .filter(candidate -> !accepted.contains(candidate)).findFirst().orElseThrow();
    }

    /**
     * Builds the body of a confirmation request.
     *
     * @param code the code.
     * @return the JSON body.
     */
    private static String codeBody(final String code) {
        return "{\"code\":\"" + code + "\"}";
    }
}
