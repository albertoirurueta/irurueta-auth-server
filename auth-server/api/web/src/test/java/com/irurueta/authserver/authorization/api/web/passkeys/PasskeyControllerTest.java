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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.application.passkeys.DeletePasskeyUseCase;
import com.irurueta.authserver.authorization.application.passkeys.ListPasskeysUseCase;
import com.irurueta.authserver.authorization.application.passkeys.RenamePasskeyUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
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
 * Unit tests of {@link PasskeyController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Path of the collection. */
    private static final String PATH = "/api/account/passkeys";

    /** Credential identifier used by the tests. */
    private static final String ID = "cred-1";

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Signature counter of the passkey. */
    private static final long SIGNATURE_COUNT = 3L;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** A passkey of the account. */
    private final Passkey passkey = new Passkey(ID, "handle", "Laptop", Instant.parse("2026-01-01T00:00:00Z"), null,
            SIGNATURE_COUNT, true, false);

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the passkeys. */
    @Mock
    private ListPasskeysUseCase listPasskeysUseCase;

    /** Renames a passkey. */
    @Mock
    private RenamePasskeyUseCase renamePasskeyUseCase;

    /** Deletes a passkey. */
    @Mock
    private DeletePasskeyUseCase deletePasskeyUseCase;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Real mapper. */
    @Spy
    private PasskeyDtoMapper passkeyDtoMapper = new PasskeyDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private PasskeyController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the MockMvc and resolves the account of every request.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new PasskeyExceptionHandler(new MfaExceptionHandler())).build();
        when(currentAccountResolver.resolve()).thenReturn(account);
    }

    /**
     * Verifies that the passkeys of the account are listed without the user handle.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void listPasskeys_whenAccountHasPasskeys_answersThem() throws Exception {
        when(listPasskeysUseCase.execute(USERNAME)).thenReturn(List.of(passkey));

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(ID))
                .andExpect(jsonPath("$[0].label").value("Laptop"))
                .andExpect(jsonPath("$[0].signatureCount").value(SIGNATURE_COUNT))
                .andExpect(jsonPath("$[0].backupEligible").value(true))
                .andExpect(jsonPath("$[0].userId").doesNotExist());
    }

    /**
     * Verifies that a renamed passkey is answered.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void renamePasskey_whenPasskeyExists_answersTheRenamedPasskey() throws Exception {
        when(renamePasskeyUseCase.execute(USERNAME, ID, "Phone")).thenReturn(
                new Passkey(ID, "handle", "Phone", passkey.createdAt(), null, SIGNATURE_COUNT, true, false));

        mockMvc.perform(patch(PATH + "/" + ID).contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"Phone\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.label").value("Phone"));
    }

    /**
     * Verifies that renaming a passkey the account does not have is answered {@code 404} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void renamePasskey_whenPasskeyIsNotTheAccounts_answersNotFound() throws Exception {
        when(renamePasskeyUseCase.execute(USERNAME, ID, "Phone")).thenThrow(new PasskeyNotFoundException("none"));

        mockMvc.perform(patch(PATH + "/" + ID).contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"Phone\"}"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:passkeys:passkey-not-found"));
    }

    /**
     * Verifies that a label the use case refuses is answered {@code 400} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void renamePasskey_whenLabelIsRefused_answersBadRequest() throws Exception {
        when(renamePasskeyUseCase.execute(USERNAME, ID, "Phone")).thenThrow(new IllegalArgumentException("long"));

        mockMvc.perform(patch(PATH + "/" + ID).contentType(MediaType.APPLICATION_JSON).content("{\"label\":\"Phone\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:passkeys:invalid-label"));
    }

    /**
     * Verifies that a deleted passkey is answered {@code 204}, after the step-up check.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void deletePasskey_whenPasskeyExists_answersNoContentAfterTheStepUpCheck() throws Exception {
        mockMvc.perform(delete(PATH + "/" + ID)).andExpect(status().isNoContent()).andExpect(content().string(""));

        final var order = inOrder(stepUpGuard, deletePasskeyUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(deletePasskeyUseCase).execute(account.id(), USERNAME, ID);
    }

    /**
     * Verifies that a passkey is not deleted without a recent multi-factor sign-in.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void deletePasskey_whenStepUpIsMissing_answersUnauthorizedWithTheChallenge() throws Exception {
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(delete(PATH + "/" + ID))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"))
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));
        verifyNoInteractions(deletePasskeyUseCase);
    }

    /**
     * Verifies that deleting a passkey the account does not have is answered {@code 404} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void deletePasskey_whenPasskeyIsNotTheAccounts_answersNotFound() throws Exception {
        doThrow(new PasskeyNotFoundException("none")).when(deletePasskeyUseCase)
                .execute(account.id(), USERNAME, ID);

        mockMvc.perform(delete(PATH + "/" + ID))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("urn:problem:passkeys:passkey-not-found"));
    }
}
