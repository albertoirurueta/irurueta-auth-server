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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.application.clients.CreateClientUseCase;
import com.irurueta.authserver.authorization.application.clients.CreatedClient;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.application.clients.DeleteClientUseCase;
import com.irurueta.authserver.authorization.application.clients.GetClientUseCase;
import com.irurueta.authserver.authorization.application.clients.ListClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.RotateClientSecretUseCase;
import com.irurueta.authserver.authorization.application.clients.UpdateClientUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientAlreadyExistsException;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import java.util.List;
import java.util.Optional;
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
 * Unit tests of {@link ClientAdminController}, with a standalone MockMvc and its exception handler.
 */
@ExtendWith(MockitoExtension.class)
class ClientAdminControllerTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Base path of the endpoints. */
    private static final String BASE = "/api/admin/clients";

    /** JSON body of a valid confidential client. */
    private static final String BODY = """
            {"clientId":"%s","name":"App","confidential":true,"authMethods":["client_secret_basic"],
            "grantTypes":["authorization_code"],"redirectUris":["http://localhost/cb"],"scopes":["openid"],
            "requireProofKey":true,"accessTokenTtl":"PT5M","refreshTokenTtl":"PT1H","reuseRefreshTokens":false}""";

    /** Lists clients. */
    @Mock
    private ListClientsUseCase listClientsUseCase;

    /** Finds a client. */
    @Mock
    private GetClientUseCase getClientUseCase;

    /** Creates clients. */
    @Mock
    private CreateClientUseCase createClientUseCase;

    /** Updates clients. */
    @Mock
    private UpdateClientUseCase updateClientUseCase;

    /** Deletes clients. */
    @Mock
    private DeleteClientUseCase deleteClientUseCase;

    /** Rotates secrets. */
    @Mock
    private RotateClientSecretUseCase rotateClientSecretUseCase;

    /** Real mapper between the generated DTOs and the domain, spied so the controller is wired with it. */
    @Spy
    private ClientDtoMapper clientDtoMapper = new ClientDtoMapper(new ClientJwksParser());

    /** Controller under test. */
    @InjectMocks
    private ClientAdminController controller;

    /** Standalone MockMvc. */
    private MockMvc mockMvc;

    /**
     * Builds the standalone MockMvc with the exception handler.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ClientExceptionHandler())
                .build();
    }

    /**
     * Listing answers the public view of the clients, without any secret.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void list_whenClientsExist_returnsClientsWithoutSecrets() throws Exception {
        when(listClientsUseCase.execute()).thenReturn(List.of(bff()));

        mockMvc.perform(get(BASE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].clientId").value("bff"))
                .andExpect(jsonPath("$[0].clientSecret").doesNotExist());
    }

    /**
     * Getting a known client answers it.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void get_whenClientExists_returnsIt() throws Exception {
        when(getClientUseCase.execute("bff")).thenReturn(Optional.of(bff()));

        mockMvc.perform(get(BASE + "/bff"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value("bff"));
    }

    /**
     * Getting an unknown client answers a 404 problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void get_whenClientIsMissing_returnsNotFoundProblem() throws Exception {
        when(getClientUseCase.execute("none")).thenReturn(Optional.empty());

        mockMvc.perform(get(BASE + "/none"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("urn:problem:client:not-found"));
    }

    /**
     * Creating a confidential client answers 201 with the secret shown once.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void create_whenConfidential_returnsCreatedWithSecret() throws Exception {
        final var secret = UUID.randomUUID().toString();
        when(createClientUseCase.execute(any()))
                .thenReturn(new CreatedClient(bff(), secret));

        mockMvc.perform(post(BASE).contentType(MediaType.APPLICATION_JSON).content(BODY.formatted("bff")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.client.clientId").value("bff"))
                .andExpect(jsonPath("$.clientSecret").value(secret));
    }

    /**
     * Creating a client that already exists answers a 409 problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void create_whenClientExists_returnsConflictProblem() throws Exception {
        when(createClientUseCase.execute(any())).thenThrow(new ClientAlreadyExistsException("bff"));

        mockMvc.perform(post(BASE).contentType(MediaType.APPLICATION_JSON).content(BODY.formatted("bff")))
                .andExpect(status().isConflict())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").value("urn:problem:client:already-exists"));
    }

    /**
     * An invalid body is rejected before reaching the use case.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void create_whenBodyIsInvalid_returnsBadRequest() throws Exception {
        mockMvc.perform(post(BASE).contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"x\"}"))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(createClientUseCase);
    }

    /**
     * A definition the domain rejects answers a 400 problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void create_whenDomainRejectsDefinition_returnsBadRequestProblem() throws Exception {
        final var body = BODY.formatted("app").replace("\"confidential\":true", "\"confidential\":false")
                .replace("\"requireProofKey\":true", "\"requireProofKey\":false");

        mockMvc.perform(post(BASE).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:problem:client:invalid"));

        verifyNoInteractions(createClientUseCase);
    }

    /**
     * Updating answers the updated client.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void update_whenClientMatchesPath_updatesAndReturnsIt() throws Exception {
        mockMvc.perform(put(BASE + "/app").contentType(MediaType.APPLICATION_JSON).content(BODY.formatted("app")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value("app"));

        verify(updateClientUseCase).execute(any());
    }

    /**
     * Updating with a different identifier in the body is rejected.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void update_whenBodyIdDiffersFromPath_returnsBadRequest() throws Exception {
        mockMvc.perform(put(BASE + "/other").contentType(MediaType.APPLICATION_JSON)
                        .content(BODY.formatted("app")))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(updateClientUseCase);
    }

    /**
     * Updating an unknown client answers a 404 problem.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void update_whenClientIsMissing_returnsNotFound() throws Exception {
        doThrow(new ClientNotFoundException("app")).when(updateClientUseCase).execute(any());

        mockMvc.perform(put(BASE + "/app").contentType(MediaType.APPLICATION_JSON).content(BODY.formatted("app")))
                .andExpect(status().isNotFound());
    }

    /**
     * Deleting answers 204.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void delete_whenClientExists_returnsNoContent() throws Exception {
        mockMvc.perform(delete(BASE + "/app")).andExpect(status().isNoContent());

        verify(deleteClientUseCase).execute("app");
    }

    /**
     * Deleting an unknown client answers 404.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void delete_whenClientIsMissing_returnsNotFound() throws Exception {
        doThrow(new ClientNotFoundException("app")).when(deleteClientUseCase).execute("app");

        mockMvc.perform(delete(BASE + "/app")).andExpect(status().isNotFound());
    }

    /**
     * Rotating answers the new secret once.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void rotateSecret_whenClientIsConfidential_returnsNewSecret() throws Exception {
        final var secret = UUID.randomUUID().toString();
        when(rotateClientSecretUseCase.execute("bff")).thenReturn(secret);

        mockMvc.perform(post(BASE + "/bff/secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").value(secret));
    }

    /**
     * Rotating the secret of a public client answers 400.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void rotateSecret_whenClientIsPublic_returnsBadRequest() throws Exception {
        when(rotateClientSecretUseCase.execute("spa-public")).thenThrow(new IllegalArgumentException("public"));

        mockMvc.perform(post(BASE + "/spa-public/secret")).andExpect(status().isBadRequest());
    }

    /**
     * Builds the default {@code bff} client with a test redirect URI.
     *
     * @return the client.
     */
    private static ClientRegistration bff() {
        return DefaultClientDefinitions.bff(List.of(TEST_REDIRECT_URI), DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }
}
