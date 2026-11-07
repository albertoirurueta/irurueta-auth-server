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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
import com.irurueta.authserver.authorization.application.x509.BindCertificateUseCase;
import com.irurueta.authserver.authorization.application.x509.ListCertificatesUseCase;
import com.irurueta.authserver.authorization.application.x509.UnbindCertificateUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.time.Duration;
import java.time.Instant;
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
 * Unit tests of {@link CertificateController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class CertificateControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Path of the collection. */
    private static final String PATH = "/api/account/certificates";

    /** PEM text sent by the tests; the reader is mocked, so it is never parsed. */
    private static final String PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    /** Body of a bind request. */
    private static final String BODY = "{\"certificate\":\"" + PEM.replace("\n", "\\n") + "\"}";

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "f".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** Instant the certificate was bound. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** Identifier of the binding the tests use. */
    private final UUID bindingId = UUID.randomUUID();

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the certificates. */
    @Mock
    private ListCertificatesUseCase listCertificatesUseCase;

    /** Binds a certificate. */
    @Mock
    private BindCertificateUseCase bindCertificateUseCase;

    /** Unbinds a certificate. */
    @Mock
    private UnbindCertificateUseCase unbindCertificateUseCase;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Reads the certificate of a bind request. */
    @Mock
    private PemCertificateReader pemCertificateReader;

    /** Real mapper. */
    @Spy
    private CertificateDtoMapper certificateDtoMapper = new CertificateDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private CertificateController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the MockMvc and resolves the account of every request.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new CertificateExceptionHandler(new MfaExceptionHandler())).build();
        lenient().when(currentAccountResolver.resolve()).thenReturn(account);
    }

    /**
     * Verifies that the certificates of the account are listed without the account.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void listCertificates_whenAccountHasCertificates_answersThem() throws Exception {
        when(listCertificatesUseCase.execute(account.id())).thenReturn(List.of(binding()));

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(bindingId.toString()))
                .andExpect(jsonPath("$[0].fingerprintSha256").value(FINGERPRINT))
                .andExpect(jsonPath("$[0].subjectDn").value("CN=alice"))
                .andExpect(jsonPath("$[0].userId").doesNotExist());
    }

    /**
     * Verifies that a certificate is bound after the step-up check and answered {@code 201}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void bindCertificate_whenTheCertificateIsValid_answersCreatedAfterTheStepUpCheck() throws Exception {
        when(pemCertificateReader.read(PEM)).thenReturn(new PresentedCertificate(FINGERPRINT, "CN=alice"));
        when(bindCertificateUseCase.execute(account.id(), USERNAME, FINGERPRINT, "CN=alice")).thenReturn(binding());

        mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(bindingId.toString()));

        final var order = inOrder(stepUpGuard, pemCertificateReader, bindCertificateUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(pemCertificateReader).read(PEM);
        order.verify(bindCertificateUseCase).execute(account.id(), USERNAME, FINGERPRINT, "CN=alice");
    }

    /**
     * Verifies that nothing is read or bound without a recent multi-factor sign-in.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void bindCertificate_whenStepUpIsMissing_answersUnauthorizedWithTheChallenge() throws Exception {
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
        verifyNoInteractions(pemCertificateReader, bindCertificateUseCase);
    }

    /**
     * Verifies that a value that is not a usable certificate is answered {@code 400} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void bindCertificate_whenTheValueIsInvalid_answersBadRequest() throws Exception {
        when(pemCertificateReader.read(PEM)).thenThrow(new InvalidCertificateException("bad"));

        mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:invalid-certificate"));
        verifyNoInteractions(bindCertificateUseCase);
    }

    /**
     * Verifies that a certificate of another account is answered {@code 409} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void bindCertificate_whenTheCertificateBelongsToAnotherAccount_answersConflict() throws Exception {
        when(pemCertificateReader.read(PEM)).thenReturn(new PresentedCertificate(FINGERPRINT, "CN=alice"));
        when(bindCertificateUseCase.execute(any(), any(), any(), any()))
                .thenThrow(new CertificateAlreadyBoundException("taken"));

        mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:certificate-already-bound"));
    }

    /**
     * Verifies that a request without the certificate is a bad request, never read.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void bindCertificate_whenTheCertificateIsMissing_answersBadRequest() throws Exception {
        mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
        verifyNoInteractions(pemCertificateReader, bindCertificateUseCase);
    }

    /**
     * Verifies that a certificate is unbound after the step-up check and answered {@code 204}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unbindCertificate_whenTheCertificateExists_answersNoContentAfterTheStepUpCheck() throws Exception {
        mockMvc.perform(delete(PATH + "/" + bindingId)).andExpect(status().isNoContent())
                .andExpect(content().string(""));

        final var order = inOrder(stepUpGuard, unbindCertificateUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(unbindCertificateUseCase).execute(account.id(), USERNAME, bindingId);
    }

    /**
     * Verifies that a certificate is not unbound without a recent multi-factor sign-in.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unbindCertificate_whenStepUpIsMissing_answersUnauthorized() throws Exception {
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(delete(PATH + "/" + bindingId)).andExpect(status().isUnauthorized());
        verifyNoInteractions(unbindCertificateUseCase);
    }

    /**
     * Verifies that a certificate the account does not have is answered {@code 404}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unbindCertificate_whenTheCertificateIsNotTheAccounts_answersNotFound() throws Exception {
        doThrow(new CertificateNotFoundException("none")).when(unbindCertificateUseCase)
                .execute(account.id(), USERNAME, bindingId);

        mockMvc.perform(delete(PATH + "/" + bindingId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:certificate-not-found"));
    }

    /**
     * Verifies that the last way to sign in is answered {@code 409}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unbindCertificate_whenItIsTheLastSignInMethod_answersConflict() throws Exception {
        doThrow(new LastSignInMethodException("last")).when(unbindCertificateUseCase)
                .execute(account.id(), USERNAME, bindingId);

        mockMvc.perform(delete(PATH + "/" + bindingId))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:certificate:last-sign-in-method"));
    }

    /**
     * Builds the binding used by the tests.
     *
     * @return the binding.
     */
    private CertificateBinding binding() {
        return new CertificateBinding(bindingId, account.id(), FINGERPRINT, "CN=alice", CREATED_AT);
    }
}
