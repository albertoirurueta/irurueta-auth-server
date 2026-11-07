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

package com.irurueta.authserver.authorization.api.web.social;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.api.web.mfa.StepUpGuard;
import com.irurueta.authserver.authorization.application.social.ListIdentitiesUseCase;
import com.irurueta.authserver.authorization.application.social.UnlinkIdentityUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
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
 * Unit tests of {@link IdentityController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class IdentityControllerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Path of the collection. */
    private static final String PATH = "/api/account/identities";

    /** Maximum age of the step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** Identifier of the identity the tests unlink. */
    private final UUID identityId = UUID.randomUUID();

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the identities. */
    @Mock
    private ListIdentitiesUseCase listIdentitiesUseCase;

    /** Unlinks an identity. */
    @Mock
    private UnlinkIdentityUseCase unlinkIdentityUseCase;

    /** Requires a recent multi-factor sign-in. */
    @Mock
    private StepUpGuard stepUpGuard;

    /** Real mapper. */
    @Spy
    private IdentityDtoMapper identityDtoMapper = new IdentityDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private IdentityController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the MockMvc and resolves the account of every request.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new IdentityExceptionHandler(new MfaExceptionHandler())).build();
        lenient().when(currentAccountResolver.resolve()).thenReturn(account);
    }

    /**
     * Verifies that the identities of the account are listed without the subject.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void listIdentities_whenAccountHasIdentities_answersThem() throws Exception {
        when(listIdentitiesUseCase.execute(account.id())).thenReturn(List.of(new FederatedIdentity(identityId,
                account.id(), IdentityProvider.GOOGLE, "subject", "alice@example.org",
                Instant.parse("2026-01-01T00:00:00Z"), null)));

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(identityId.toString()))
                .andExpect(jsonPath("$[0].provider").value("google"))
                .andExpect(jsonPath("$[0].email").value("alice@example.org"))
                .andExpect(jsonPath("$[0].subject").doesNotExist());
    }

    /**
     * Verifies that an account without identities gets an empty list.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void listIdentities_whenAccountHasNone_answersAnEmptyList() throws Exception {
        when(listIdentitiesUseCase.execute(account.id())).thenReturn(List.of());

        mockMvc.perform(get(PATH)).andExpect(status().isOk()).andExpect(content().json("[]"));
    }

    /**
     * Verifies that an unlinked identity is answered {@code 204}, after the step-up check.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unlinkIdentity_whenIdentityExists_answersNoContentAfterTheStepUpCheck() throws Exception {
        mockMvc.perform(delete(PATH + "/" + identityId)).andExpect(status().isNoContent())
                .andExpect(content().string(""));

        final var order = inOrder(stepUpGuard, unlinkIdentityUseCase);
        order.verify(stepUpGuard).requireRecentMultiFactor(account.id());
        order.verify(unlinkIdentityUseCase).execute(account.id(), USERNAME, identityId);
    }

    /**
     * Verifies that an identity is not unlinked without a recent multi-factor sign-in.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unlinkIdentity_whenStepUpIsMissing_answersUnauthorizedWithTheChallenge() throws Exception {
        doThrow(new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES))).when(stepUpGuard).requireRecentMultiFactor(account.id());

        mockMvc.perform(delete(PATH + "/" + identityId))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"))
                .andExpect(jsonPath("$.type").value("urn:problem:mfa:insufficient-user-authentication"));
        verifyNoInteractions(unlinkIdentityUseCase);
    }

    /**
     * Verifies that unlinking an identity the account does not have is answered {@code 404} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unlinkIdentity_whenIdentityIsNotTheAccounts_answersNotFound() throws Exception {
        doThrow(new FederatedIdentityNotFoundException("none")).when(unlinkIdentityUseCase)
                .execute(account.id(), USERNAME, identityId);

        mockMvc.perform(delete(PATH + "/" + identityId))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:identity:identity-not-found"));
    }

    /**
     * Verifies that unlinking the last way to sign in is answered {@code 409} as a problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unlinkIdentity_whenIdentityIsTheLastSignInMethod_answersConflict() throws Exception {
        doThrow(new LastSignInMethodException("last")).when(unlinkIdentityUseCase)
                .execute(account.id(), USERNAME, identityId);

        mockMvc.perform(delete(PATH + "/" + identityId))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:problem:identity:last-sign-in-method"));
    }

    /**
     * Verifies that an identifier that is not a UUID is a bad request, not a server error.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void unlinkIdentity_whenIdIsNotAUuid_answersBadRequest() throws Exception {
        mockMvc.perform(delete(PATH + "/not-a-uuid")).andExpect(status().isBadRequest());
        verifyNoInteractions(unlinkIdentityUseCase);
    }
}
