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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.mfa.ListTrustedDevicesUseCase;
import com.irurueta.authserver.authorization.application.mfa.RevokeTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
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
 * Unit tests of {@link TrustedDeviceController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class TrustedDeviceControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Path of the collection. */
    private static final String PATH = "/api/account/trusted-devices";

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the devices. */
    @Mock
    private ListTrustedDevicesUseCase listTrustedDevicesUseCase;

    /** Revokes a device. */
    @Mock
    private RevokeTrustedDeviceUseCase revokeTrustedDeviceUseCase;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Real mapper. */
    @Spy
    private TrustedDeviceDtoMapper trustedDeviceDtoMapper = new TrustedDeviceDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private TrustedDeviceController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the MockMvc and resolves the account of every request.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new MfaExceptionHandler()).build();
        when(currentAccountResolver.resolve()).thenReturn(account);
    }

    /**
     * Verifies that the devices of the account are listed.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void listTrustedDevices_whenAccountHasDevices_answersThem() throws Exception {
        final var id = UUID.randomUUID();
        when(listTrustedDevicesUseCase.execute(account.id())).thenReturn(List.of(new TrustedDevice(id,
                account.id(), "hash", "Firefox", Instant.parse("2026-02-01T00:00:00Z"),
                Instant.parse("2026-01-01T00:00:00Z"))));

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(id.toString()))
                .andExpect(jsonPath("$[0].userAgentSummary").value("Firefox"))
                .andExpect(jsonPath("$[0].hashedToken").doesNotExist());
    }

    /**
     * Verifies that a revoked device is answered {@code 204}.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void revokeTrustedDevice_whenDeviceExists_answersNoContent() throws Exception {
        final var id = UUID.randomUUID();
        when(revokeTrustedDeviceUseCase.execute(account.id(), USERNAME, id)).thenReturn(true);

        mockMvc.perform(delete(PATH + "/" + id)).andExpect(status().isNoContent()).andExpect(content().string(""));
        verify(stepUpGuard).requireRecentMultiFactor(account.id());
    }

    /**
     * Verifies that a device is not revoked without a recent multi-factor sign-in.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void revokeTrustedDevice_whenStepUpIsMissing_answersUnauthorized() throws Exception {
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(delete(PATH + "/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
        verifyNoInteractions(revokeTrustedDeviceUseCase);
    }

    /**
     * Verifies that a missing device, or one of another account, is answered {@code 404} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void revokeTrustedDevice_whenDeviceIsNotTheAccounts_answersNotFound() throws Exception {
        final var id = UUID.randomUUID();
        when(revokeTrustedDeviceUseCase.execute(account.id(), USERNAME, id)).thenReturn(false);

        mockMvc.perform(delete(PATH + "/" + id))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:trusted-device-not-found"));
    }
}
