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

import com.irurueta.authserver.authorization.application.clients.CreateClientUseCase;
import com.irurueta.authserver.authorization.application.clients.DeleteClientUseCase;
import com.irurueta.authserver.authorization.application.clients.GetClientUseCase;
import com.irurueta.authserver.authorization.application.clients.ListClientsUseCase;
import com.irurueta.authserver.authorization.application.clients.RotateClientSecretUseCase;
import com.irurueta.authserver.authorization.application.clients.UpdateClientUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration of the registered clients. Secrets are never returned, except once when a confidential client is
 * created or its secret is rotated. Failures are answered as problem details by {@link ClientExceptionHandler}.
 */
@RestController
@RequestMapping("/api/admin/clients")
@Tag(name = "Clients", description = "Administration of the registered clients")
@RequiredArgsConstructor
public class ClientAdminController {

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

    /**
     * Lists the clients.
     *
     * @return every client, without secrets.
     */
    @GetMapping
    @Operation(summary = "Lists the registered clients")
    @ApiResponse(responseCode = "200", description = "The clients")
    public List<ClientResponse> list() {
        return listClientsUseCase.execute().stream().map(ClientResponse::from).toList();
    }

    /**
     * Finds a client.
     *
     * @param clientId identifier of the client.
     * @return the client, without secret.
     * @throws ClientNotFoundException if no such client exists.
     */
    @GetMapping("/{clientId}")
    @Operation(summary = "Gets a registered client")
    @ApiResponse(responseCode = "200", description = "The client")
    @ApiResponse(responseCode = "404", description = "No such client",
            content = @Content(mediaType = "application/problem+json"))
    public ClientResponse get(@PathVariable final String clientId) {
        return getClientUseCase.execute(clientId).map(ClientResponse::from)
                .orElseThrow(() -> new ClientNotFoundException(clientId));
    }

    /**
     * Creates a client.
     *
     * @param request definition of the client.
     * @return the client and, when confidential, its generated secret (shown only once).
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Creates a client",
            description = "The generated secret of a confidential client is returned only in this answer.")
    @ApiResponse(responseCode = "201", description = "The created client")
    @ApiResponse(responseCode = "400", description = "Invalid definition",
            content = @Content(mediaType = "application/problem+json"))
    @ApiResponse(responseCode = "409", description = "The client identifier is already registered",
            content = @Content(mediaType = "application/problem+json"))
    public CreatedClientResponse create(@Valid @RequestBody final ClientRequest request) {
        return CreatedClientResponse.from(createClientUseCase.execute(request.toRegistration()));
    }

    /**
     * Replaces the definition of a client. Its secret is kept.
     *
     * @param clientId identifier of the client.
     * @param request  new definition; its identifier must match the path.
     * @return the updated client.
     * @throws IllegalArgumentException if the identifier in the body differs from the path.
     */
    @PutMapping("/{clientId}")
    @Operation(summary = "Updates a client", description = "The secret of the client is not changed.")
    @ApiResponse(responseCode = "200", description = "The updated client")
    @ApiResponse(responseCode = "400", description = "Invalid definition",
            content = @Content(mediaType = "application/problem+json"))
    @ApiResponse(responseCode = "404", description = "No such client",
            content = @Content(mediaType = "application/problem+json"))
    public ClientResponse update(@PathVariable final String clientId, @Valid @RequestBody final ClientRequest request) {
        if (!clientId.equals(request.clientId())) {
            throw new IllegalArgumentException("The clientId of the body must match the path");
        }
        final var registration = request.toRegistration();
        updateClientUseCase.execute(registration);
        return ClientResponse.from(registration);
    }

    /**
     * Deletes a client.
     *
     * @param clientId identifier of the client.
     */
    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Deletes a client")
    @ApiResponse(responseCode = "204", description = "Client deleted")
    @ApiResponse(responseCode = "404", description = "No such client",
            content = @Content(mediaType = "application/problem+json"))
    public void delete(@PathVariable final String clientId) {
        deleteClientUseCase.execute(clientId);
    }

    /**
     * Generates a new secret for a confidential client.
     *
     * @param clientId identifier of the client.
     * @return the new secret (shown only once).
     */
    @PostMapping("/{clientId}/secret")
    @Operation(summary = "Rotates the secret of a confidential client",
            description = "The new secret is returned only in this answer.")
    @ApiResponse(responseCode = "200", description = "The new secret")
    @ApiResponse(responseCode = "400", description = "The client is public",
            content = @Content(mediaType = "application/problem+json"))
    @ApiResponse(responseCode = "404", description = "No such client",
            content = @Content(mediaType = "application/problem+json"))
    public ClientSecretResponse rotateSecret(@PathVariable final String clientId) {
        return new ClientSecretResponse(rotateClientSecretUseCase.execute(clientId));
    }
}
