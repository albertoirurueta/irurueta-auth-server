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

package com.irurueta.authserver.authorization.api.web.account;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.account.ChangePasswordUseCase;
import com.irurueta.authserver.authorization.application.account.RegisterAccountUseCase;
import com.irurueta.authserver.authorization.application.account.RequestPasswordResetUseCase;
import com.irurueta.authserver.authorization.application.account.ResetPasswordUseCase;
import com.irurueta.authserver.authorization.application.account.VerifyEmailUseCase;
import com.irurueta.authserver.authorization.domain.account.AccountMailException;
import com.irurueta.authserver.authorization.domain.account.InvalidAccountTokenException;
import com.irurueta.authserver.authorization.domain.password.InvalidCredentialsException;
import com.irurueta.authserver.authorization.domain.password.InvalidPasswordException;
import com.irurueta.authserver.authorization.domain.password.PasswordViolation;
import java.security.Principal;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Unit tests of {@link AccountController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class AccountControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Client address of the requests made by MockMvc. */
    private static final String CLIENT_ADDRESS = "127.0.0.1";

    /** Seconds until a rate-limited client may retry. */
    private static final long RETRY_SECONDS = 42;

    /** Registers accounts. */
    @Mock
    private RegisterAccountUseCase registerAccountUseCase;

    /** Verifies e-mail addresses. */
    @Mock
    private VerifyEmailUseCase verifyEmailUseCase;

    /** Changes passwords. */
    @Mock
    private ChangePasswordUseCase changePasswordUseCase;

    /** Requests password resets. */
    @Mock
    private RequestPasswordResetUseCase requestPasswordResetUseCase;

    /** Resets passwords. */
    @Mock
    private ResetPasswordUseCase resetPasswordUseCase;

    /** Limits the unauthenticated requests. */
    @Mock
    private AccountRateLimiter accountRateLimiter;

    /** Controller under test. */
    @InjectMocks
    private AccountController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /** Value built at runtime, used as a password. */
    private String secret;

    /**
     * Builds the MockMvc and a fresh runtime value.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new AccountExceptionHandler()).build();
        secret = UUID.randomUUID().toString();
    }

    /**
     * Checks that registration is accepted and delegated.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void register_whenRequestIsValid_answersAcceptedAndDelegates() throws Exception {
        mockMvc.perform(post("/api/account/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", USERNAME, "email", EMAIL, "password", secret)))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));

        verify(accountRateLimiter).check(CLIENT_ADDRESS, EMAIL);
        verify(registerAccountUseCase).execute(USERNAME, EMAIL, secret);
    }

    /**
     * Checks that a registration over the limit is answered {@code 429} with a {@code Retry-After} header and never
     * reaches the use case.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void register_whenRateLimitIsExceeded_answersTooManyRequests() throws Exception {
        doThrow(new AccountRateLimitExceededException(Duration.ofSeconds(RETRY_SECONDS)))
                .when(accountRateLimiter).check(CLIENT_ADDRESS, EMAIL);

        mockMvc.perform(post("/api/account/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", USERNAME, "email", EMAIL, "password", secret)))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, Long.toString(RETRY_SECONDS)))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

        verifyNoInteractions(registerAccountUseCase);
    }

    /**
     * Checks that a registration whose e-mail cannot be delivered is answered {@code 503}: the use case rolled the
     * registration back, so the user can retry.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void register_whenMailCannotBeDelivered_answersServiceUnavailable() throws Exception {
        doThrow(new AccountMailException("down", new IllegalStateException("relay")))
                .when(registerAccountUseCase).execute(USERNAME, EMAIL, secret);

        mockMvc.perform(post("/api/account/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", USERNAME, "email", EMAIL, "password", secret)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }

    /**
     * Checks that an invalid e-mail is rejected before reaching the use case.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void register_whenEmailIsMalformed_answersProblemDetail() throws Exception {
        mockMvc.perform(post("/api/account/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", USERNAME, "email", "not-an-email", "password", secret)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

        verifyNoInteractions(registerAccountUseCase);
    }

    /**
     * Checks that a rejected password is answered as a problem detail listing the rules.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void register_whenPasswordBreaksPolicy_answersProblemDetail() throws Exception {
        doThrow(new InvalidPasswordException(List.of(PasswordViolation.TOO_SHORT)))
                .when(registerAccountUseCase).execute(USERNAME, EMAIL, secret);

        mockMvc.perform(post("/api/account/register").contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", USERNAME, "email", EMAIL, "password", secret)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.violations[0]").value("TOO_SHORT"));
    }

    /**
     * Checks that a valid token verifies the address.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void verify_whenTokenIsValid_answersNoContent() throws Exception {
        mockMvc.perform(get("/api/account/verify").param("token", secret))
                .andExpect(status().isNoContent());

        verify(accountRateLimiter).check(CLIENT_ADDRESS, null);
        verify(verifyEmailUseCase).execute(secret);
    }

    /**
     * Checks that an invalid token is answered as a problem detail.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void verify_whenTokenIsInvalid_answersProblemDetail() throws Exception {
        doThrow(new InvalidAccountTokenException()).when(verifyEmailUseCase).execute(secret);

        mockMvc.perform(get("/api/account/verify").param("token", secret))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Invalid token"));
    }

    /**
     * Checks that the password of the authenticated principal is changed.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void changePassword_whenRequestIsValid_changesPasswordOfPrincipal() throws Exception {
        final var next = UUID.randomUUID().toString();
        final Principal principal = () -> USERNAME;

        mockMvc.perform(post("/api/account/password").principal(principal)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("currentPassword", secret, "newPassword", next)))
                .andExpect(status().isNoContent());

        verify(changePasswordUseCase).execute(USERNAME, secret, next);
    }

    /**
     * Checks that a blank new password is rejected before reaching the use case.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void changePassword_whenNewPasswordIsBlank_answersBadRequest() throws Exception {
        final Principal principal = () -> USERNAME;

        mockMvc.perform(post("/api/account/password").principal(principal)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("currentPassword", secret, "newPassword", "")))
                .andExpect(status().isBadRequest());

        verify(changePasswordUseCase, never()).execute(USERNAME, secret, "");
    }

    /**
     * Checks that a wrong current password is answered as a problem detail.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void changePassword_whenCurrentPasswordIsWrong_answersProblemDetail() throws Exception {
        final var next = UUID.randomUUID().toString();
        final Principal principal = () -> USERNAME;
        doThrow(new InvalidCredentialsException("The username or password is wrong"))
                .when(changePasswordUseCase).execute(USERNAME, secret, next);

        mockMvc.perform(post("/api/account/password").principal(principal)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("currentPassword", secret, "newPassword", next)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Invalid credentials"));
    }

    /**
     * Checks that a reset request is accepted and delegated.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void requestPasswordReset_whenEmailIsValid_answersAcceptedAndDelegates() throws Exception {
        mockMvc.perform(post("/api/account/password/reset-request").contentType(MediaType.APPLICATION_JSON)
                        .content(json("email", EMAIL)))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));

        verify(accountRateLimiter).check(CLIENT_ADDRESS, EMAIL);
        verify(requestPasswordResetUseCase).execute(EMAIL);
    }

    /**
     * Checks that a reset request whose link cannot be delivered is answered exactly like any other: only a
     * registered address is mailed, so a delivery failure must not reveal that the address is registered.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void requestPasswordReset_whenMailCannotBeDelivered_stillAnswersAccepted() throws Exception {
        doThrow(new AccountMailException("down", new IllegalStateException("relay")))
                .when(requestPasswordResetUseCase).execute(EMAIL);

        mockMvc.perform(post("/api/account/password/reset-request").contentType(MediaType.APPLICATION_JSON)
                        .content(json("email", EMAIL)))
                .andExpect(status().isAccepted())
                .andExpect(content().string(""));
    }

    /**
     * Checks that a missing e-mail is rejected before reaching the use case.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void requestPasswordReset_whenEmailIsBlank_answersBadRequest() throws Exception {
        mockMvc.perform(post("/api/account/password/reset-request").contentType(MediaType.APPLICATION_JSON)
                        .content(json("email", "")))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(requestPasswordResetUseCase);
    }

    /**
     * Checks that a reset with a valid token is delegated.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void resetPassword_whenRequestIsValid_answersNoContentAndDelegates() throws Exception {
        final var token = UUID.randomUUID().toString();

        mockMvc.perform(post("/api/account/password/reset").contentType(MediaType.APPLICATION_JSON)
                        .content(json("token", token, "newPassword", secret)))
                .andExpect(status().isNoContent());

        verify(accountRateLimiter).check(CLIENT_ADDRESS, null);
        verify(resetPasswordUseCase).execute(token, secret);
    }

    /**
     * Checks that an invalid reset token is answered as a problem detail.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void resetPassword_whenTokenIsInvalid_answersProblemDetail() throws Exception {
        final var token = UUID.randomUUID().toString();
        doThrow(new InvalidAccountTokenException()).when(resetPasswordUseCase).execute(token, secret);

        mockMvc.perform(post("/api/account/password/reset").contentType(MediaType.APPLICATION_JSON)
                        .content(json("token", token, "newPassword", secret)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }

    /**
     * Builds a JSON object from key and value pairs.
     *
     * @param pairs alternating keys and values.
     * @return the JSON text.
     */
    private static String json(final String... pairs) {
        final var builder = new StringBuilder("{");
        for (var i = 0; i < pairs.length; i += 2) {
            if (i > 0) {
                builder.append(',');
            }
            builder.append('"').append(pairs[i]).append("\":\"").append(pairs[i + 1]).append('"');
        }
        return builder.append('}').toString();
    }
}
