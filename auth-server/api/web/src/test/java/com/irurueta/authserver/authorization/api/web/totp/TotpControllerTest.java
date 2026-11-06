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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.application.totp.ConfirmTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.DisableTotpUseCase;
import com.irurueta.authserver.authorization.application.totp.EnrollTotpUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.totp.InvalidTotpCodeException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Unit tests of {@link TotpController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class TotpControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Path of the enrolment. */
    private static final String PATH = "/api/account/totp";

    /** Path of the confirmation. */
    private static final String CONFIRM_PATH = PATH + "/confirm";

    /** URI of the enrolment. */
    private static final String URI = "otpauth://totp/Issuer:alice?secret=ABC";

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Starts an enrolment. */
    @Mock
    private EnrollTotpUseCase enrollTotpUseCase;

    /** Confirms an enrolment. */
    @Mock
    private ConfirmTotpUseCase confirmTotpUseCase;

    /** Disables the authenticator app. */
    @Mock
    private DisableTotpUseCase disableTotpUseCase;

    /** Renders the QR code. */
    @Mock
    private QrCodeRenderer qrCodeRenderer;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Real mapper. */
    @Spy
    private TotpDtoMapper totpDtoMapper = new TotpDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private TotpController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the MockMvc.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new MfaExceptionHandler()).build();
    }

    /**
     * Verifies that an enrolment answers the URI and the QR code, and is never cached.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void enrollTotp_whenAccountIsNotEnrolled_answersUriAndQrCode() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(enrollTotpUseCase.execute(account.id(), USERNAME)).thenReturn(URI);
        when(qrCodeRenderer.render(URI)).thenReturn("data:image/png;base64,AA");

        mockMvc.perform(post(PATH))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.otpauthUri").value(URI))
                .andExpect(jsonPath("$.qrCode").value("data:image/png;base64,AA"));
    }

    /**
     * Verifies that enrolling twice is answered {@code 409}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void enrollTotp_whenAlreadyEnabled_answersConflict() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(enrollTotpUseCase.execute(account.id(), USERNAME)).thenThrow(new TotpAlreadyEnabledException("on"));

        mockMvc.perform(post(PATH)).andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:totp-already-enabled"));
    }

    /**
     * Verifies that a confirmation answers the recovery codes, never cached.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void confirmTotp_whenCodeIsRight_answersRecoveryCodes() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(confirmTotpUseCase.execute(account.id(), "123456")).thenReturn(List.of("AAAA", "BBBB"));

        mockMvc.perform(post(CONFIRM_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.recoveryCodes[0]").value("AAAA"))
                .andExpect(jsonPath("$.remaining").value(2));
    }

    /**
     * Verifies that a wrong code is answered {@code 400}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void confirmTotp_whenCodeIsWrong_answersBadRequest() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(confirmTotpUseCase.execute(account.id(), "123456")).thenThrow(new InvalidTotpCodeException("no"));

        mockMvc.perform(post(CONFIRM_PATH).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:invalid-code"));
    }

    /**
     * Verifies that disabling answers {@code 204} and delegates.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void disableTotp_whenCalled_answersNoContentAndDelegates() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);

        mockMvc.perform(delete(PATH)).andExpect(status().isNoContent()).andExpect(content().string(""));

        verify(stepUpGuard).requireRecentMultiFactor(account.id());
        verify(disableTotpUseCase).execute(account.id(), USERNAME);
    }

    /**
     * Verifies that disabling without a recent multi-factor sign-in is answered with the step-up challenge and
     * removes nothing.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void disableTotp_whenStepUpIsMissing_answersUnauthorizedWithTheChallenge() throws Exception {
        when(currentAccountResolver.resolve()).thenReturn(account);
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(delete(PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"insufficient_user_authentication\", "
                        + "acr_values=\"urn:irurueta:acr:mfa\", max_age=\"300\""))
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));

        verifyNoInteractions(disableTotpUseCase);
    }
}
