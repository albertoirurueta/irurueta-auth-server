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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.application.sms.ConfirmPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.FindUserPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.InvalidPhoneNumberException;
import com.irurueta.authserver.authorization.application.sms.PhoneEnrolmentStarted;
import com.irurueta.authserver.authorization.application.sms.RemovePhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import com.irurueta.authserver.authorization.application.sms.StartPhoneEnrolmentUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/** Unit tests of {@link PhoneController}, with a standalone MockMvc. */
@ExtendWith(MockitoExtension.class)
class PhoneControllerTest {

    /** Path of the phone. */
    private static final String PATH = "/api/account/phone";

    /** Path of the verification. */
    private static final String VERIFY_PATH = PATH + "/verify";

    /** Address of the client. */
    private static final String CLIENT = "192.0.2.7";

    /** How long a verification code lives. */
    private static final Duration CODE_LIFETIME = Duration.ofMinutes(10);

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), "alice");

    /** The verified phone of the account. */
    private final UserPhone phone = new UserPhone(account.id(), new PhoneNumber("+34600111222"), Instant.EPOCH);

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Finds the verified phone. */
    @Mock
    private FindUserPhoneUseCase findUserPhoneUseCase;

    /** Starts an enrolment. */
    @Mock
    private StartPhoneEnrolmentUseCase startPhoneEnrolmentUseCase;

    /** Confirms an enrolment. */
    @Mock
    private ConfirmPhoneUseCase confirmPhoneUseCase;

    /** Removes the phone. */
    @Mock
    private RemovePhoneUseCase removePhoneUseCase;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Limits the requests. */
    @Mock
    private OttRateLimiter rateLimiter;

    /** Real mapper. */
    @Spy
    private PhoneDtoMapper phoneDtoMapper = new PhoneDtoMapper();

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /** Builds the controller, bound to a request that comes from a known client, and the MockMvc. */
    @BeforeEach
    void setUp() {
        final var request = new MockHttpServletRequest();
        request.setRemoteAddr(CLIENT);
        final var controller = new PhoneController(currentAccountResolver, findUserPhoneUseCase,
                startPhoneEnrolmentUseCase, confirmPhoneUseCase, removePhoneUseCase, stepUpGuard, rateLimiter,
                phoneDtoMapper, request);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new OttExceptionHandler(new MfaExceptionHandler())).build();
    }

    /** The verified phone is answered masked and never cached. */
    @Test
    void getPhone_whenTheAccountHasAPhone_answersItMasked() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(findUserPhoneUseCase.execute(account.id())).thenReturn(Optional.of(phone));

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.maskedNumber").value("+*******1222"))
                .andExpect(jsonPath("$.verifiedAt").exists());
    }

    /** An account without a phone is answered not found. */
    @Test
    void getPhone_whenTheAccountHasNoPhone_answersNotFound() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(findUserPhoneUseCase.execute(account.id())).thenReturn(Optional.empty());

        mockMvc.perform(get(PATH))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:phone:phone-not-found"));
    }

    /** An enrolment is limited, started and answered accepted. */
    @Test
    void startPhoneEnrolment_whenTheNumberIsValid_answersAccepted() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(startPhoneEnrolmentUseCase.execute(account.id(), "600 11 12 22"))
                .thenReturn(new PhoneEnrolmentStarted(CODE_LIFETIME));

        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"600 11 12 22\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.expiresIn").value("PT10M"));

        final var order = inOrder(stepUpGuard, rateLimiter, startPhoneEnrolmentUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(rateLimiter).checkGeneration(CLIENT, "phone:" + account.id());
        order.verify(startPhoneEnrolmentUseCase).execute(account.id(), "600 11 12 22");
    }

    /**
     * Without a recent multi-factor sign-in, an account with a confirmed second factor cannot start replacing its
     * phone: the challenge is answered, and nothing is limited or sent.
     */
    @Test
    void startPhoneEnrolment_whenStepUpIsRequired_answersTheChallengeAndSendsNothing() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(any());

        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"600 11 12 22\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));

        verifyNoInteractions(startPhoneEnrolmentUseCase, rateLimiter);
    }

    /** A number that is not a phone number is answered bad request. */
    @Test
    void startPhoneEnrolment_whenTheNumberIsNotAPhone_answersBadRequest() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(startPhoneEnrolmentUseCase.execute(account.id(), "abc")).thenThrow(new InvalidPhoneNumberException());

        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"abc\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:phone:invalid-phone"));
    }

    /** A country that gets no SMS is answered bad request. */
    @Test
    void startPhoneEnrolment_whenTheCountryIsNotAllowed_answersBadRequest() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(startPhoneEnrolmentUseCase.execute(account.id(), "+1 202 555 0100"))
                .thenThrow(new SmsCountryNotAllowedException());

        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"+1 202 555 0100\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:phone:country-not-allowed"));
    }

    /** A blank number is refused by the contract's validation before anything runs. */
    @Test
    void startPhoneEnrolment_whenTheNumberIsBlank_answersBadRequestWithoutStarting() throws Exception {
        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"  \"}"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(startPhoneEnrolmentUseCase);
    }

    /** A client over its limit is told to wait, before anything is sent. */
    @Test
    void startPhoneEnrolment_whenOverTheLimit_answersTooManyRequests() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        doThrow(new OttRateLimitExceededException(Duration.ofSeconds(2))).when(rateLimiter)
                .checkGeneration(CLIENT, "phone:" + account.id());

        mockMvc.perform(put(PATH).contentType(MediaType.APPLICATION_JSON).content("{\"phone\":\"+34600111222\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "2"))
                .andExpect(jsonPath("$.type").value("urn:problem:phone:rate-limited"));

        verifyNoInteractions(startPhoneEnrolmentUseCase);
    }

    /** A correct code verifies the phone and answers it masked. */
    @Test
    void verifyPhone_whenTheCodeIsCorrect_answersThePhone() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(confirmPhoneUseCase.execute(account.id(), account.username(), "123456")).thenReturn(true);
        when(findUserPhoneUseCase.execute(account.id())).thenReturn(Optional.of(phone));

        mockMvc.perform(post(VERIFY_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.maskedNumber").value("+*******1222"));

        verify(rateLimiter).checkVerification(CLIENT, "phone:" + account.id());
    }

    /** A wrong code is answered bad request. */
    @Test
    void verifyPhone_whenTheCodeIsWrong_answersBadRequest() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(confirmPhoneUseCase.execute(account.id(), account.username(), "123456")).thenReturn(false);

        mockMvc.perform(post(VERIFY_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:phone:invalid-code"));
    }

    /** A code that is not numeric is refused by the contract's validation. */
    @Test
    void verifyPhone_whenTheCodeIsNotNumeric_answersBadRequestWithoutVerifying() throws Exception {
        mockMvc.perform(post(VERIFY_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"abcdef\"}"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(confirmPhoneUseCase);
    }

    /** Verifications are limited too. */
    @Test
    void verifyPhone_whenOverTheLimit_answersTooManyRequestsWithoutVerifying() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        doThrow(new OttRateLimitExceededException(Duration.ofSeconds(1))).when(rateLimiter)
                .checkVerification(CLIENT, "phone:" + account.id());

        mockMvc.perform(post(VERIFY_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isTooManyRequests());

        verifyNoInteractions(confirmPhoneUseCase);
    }

    /** Removing the phone needs the step-up first, then removes it. */
    @Test
    void removePhone_whenStepUpIsSatisfied_removesThePhone() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);

        mockMvc.perform(delete(PATH)).andExpect(status().isNoContent());

        final var order = inOrder(stepUpGuard, removePhoneUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(removePhoneUseCase).execute(account.id(), account.username());
    }

    /** Without a recent multi-factor sign-in the phone is kept and the challenge is answered. */
    @Test
    void removePhone_whenStepUpIsRequired_answersTheChallengeAndKeepsThePhone() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(any());

        mockMvc.perform(delete(PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));

        verifyNoInteractions(removePhoneUseCase);
    }
}
