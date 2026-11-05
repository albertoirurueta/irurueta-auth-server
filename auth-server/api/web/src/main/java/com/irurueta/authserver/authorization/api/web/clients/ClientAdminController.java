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

import com.irurueta.authserver.authorization.api.web.v1.generated.api.ClientsApi;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientSecretResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.CreatedClientResponse;
import com.irurueta.authserver.authorization.application.clients.CreateClientUseCase;
import com.irurueta.authserver.authorization.application.clients.DeleteClientUseCase;
import com.irurueta.authserver.authorization.application.clients.GetClientUseCase;
import com.irurueta.authserver.authorization.application.clients.ListClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.RotateClientSecretUseCase;
import com.irurueta.authserver.authorization.application.clients.UpdateClientUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration of the registered clients, as the contract
 * {@code apis/auth-server/rest-server/auth-server-api-v1.yaml} describes it through the generated {@link ClientsApi}.
 * Secrets are never returned, except once when a confidential client is created or its secret is rotated. Failures
 * are answered as problem details by {@link ClientExceptionHandler}.
 */
@RestController
@RequiredArgsConstructor
public class ClientAdminController implements ClientsApi {

    /** Lists the clients. */
    private final ListClientsUseCase listClientsUseCase;

    /** Finds a client. */
    private final GetClientUseCase getClientUseCase;

    /** Creates clients. */
    private final CreateClientUseCase createClientUseCase;

    /** Updates clients. */
    private final UpdateClientUseCase updateClientUseCase;

    /** Deletes clients. */
    private final DeleteClientUseCase deleteClientUseCase;

    /** Rotates client secrets. */
    private final RotateClientSecretUseCase rotateClientSecretUseCase;

    /** Maps between the generated DTOs and the domain. */
    private final ClientDtoMapper clientDtoMapper;

    /**
     * Lists the clients.
     *
     * @return every client, without secrets.
     */
    @Override
    public ResponseEntity<List<ClientResponse>> listClients() {
        return ResponseEntity.ok(clientDtoMapper.toResponses(listClientsUseCase.execute()));
    }

    /**
     * Finds a client.
     *
     * @param clientId identifier of the client.
     * @return the client, without secret.
     * @throws ClientNotFoundException if no such client exists.
     */
    @Override
    public ResponseEntity<ClientResponse> getClient(final String clientId) {
        return ResponseEntity.ok(getClientUseCase.execute(clientId).map(clientDtoMapper::toResponse)
                .orElseThrow(() -> new ClientNotFoundException(clientId)));
    }

    /**
     * Creates a client.
     *
     * @param request definition of the client.
     * @return {@code 201 Created} with the client and, when confidential, its generated secret (shown only once).
     */
    @Override
    public ResponseEntity<CreatedClientResponse> createClient(final ClientRequest request) {
        final var created = createClientUseCase.execute(clientDtoMapper.toRegistration(request));
        return ResponseEntity.status(HttpStatus.CREATED).body(clientDtoMapper.toCreatedResponse(created));
    }

    /**
     * Replaces the definition of a client. Its secret is kept.
     *
     * @param clientId identifier of the client.
     * @param request  new definition; its identifier must match the path.
     * @return the updated client.
     * @throws IllegalArgumentException if the identifier in the body differs from the path.
     */
    @Override
    public ResponseEntity<ClientResponse> updateClient(final String clientId, final ClientRequest request) {
        if (!clientId.equals(request.clientId())) {
            throw new IllegalArgumentException("The clientId of the body must match the path");
        }
        final var registration = clientDtoMapper.toRegistration(request);
        updateClientUseCase.execute(registration);
        return ResponseEntity.ok(clientDtoMapper.toResponse(registration));
    }

    /**
     * Deletes a client.
     *
     * @param clientId identifier of the client.
     * @return {@code 204 No Content}.
     */
    @Override
    public ResponseEntity<Void> deleteClient(final String clientId) {
        deleteClientUseCase.execute(clientId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Generates a new secret for a confidential client.
     *
     * @param clientId identifier of the client.
     * @return the new secret (shown only once).
     */
    @Override
    public ResponseEntity<ClientSecretResponse> rotateClientSecret(final String clientId) {
        return ResponseEntity.ok(clientDtoMapper.toSecretResponse(rotateClientSecretUseCase.execute(clientId)));
    }
}
