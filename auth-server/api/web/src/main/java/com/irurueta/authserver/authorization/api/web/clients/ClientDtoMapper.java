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

import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientRequest;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.ClientSecretResponse;
import com.irurueta.authserver.authorization.api.web.v1.generated.model.CreatedClientResponse;
import com.irurueta.authserver.authorization.application.clients.CreatedClient;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Maps between the DTOs generated from the contract and the client registrations of the domain, so a domain model is
 * never returned from {@link ClientAdminController}.
 */
@Component
public class ClientDtoMapper {

    /**
     * Maps a create or update request to a client registration. An absent flag is {@code false}, absent audiences
     * are empty (the client identifier is then used), absent post-logout redirect URIs are empty and an absent or
     * blank format is {@value ClientRegistration#FORMAT_SELF_CONTAINED}.
     *
     * @param request the validated request.
     * @return the registration.
     * @throws IllegalArgumentException if the registration is not valid.
     */
    public ClientRegistration toRegistration(final ClientRequest request) {
        final var format = StringUtils.hasText(request.accessTokenFormat())
                ? request.accessTokenFormat() : ClientRegistration.FORMAT_SELF_CONTAINED;
        final var audiences = request.audiences() == null ? List.<String>of() : request.audiences();
        return new ClientRegistration(request.clientId(), request.name(), Boolean.TRUE.equals(request.confidential()),
                request.authMethods(), request.grantTypes(), request.redirectUris(), request.scopes(),
                Boolean.TRUE.equals(request.requireProofKey()), audiences, request.accessTokenTtl(),
                request.refreshTokenTtl(), format, Boolean.TRUE.equals(request.reuseRefreshTokens()),
                request.postLogoutRedirectUris() == null ? List.of() : request.postLogoutRedirectUris(),
                Boolean.TRUE.equals(request.requireConsent()));
    }

    /**
     * Maps a registration to its public view, which never contains a secret.
     *
     * @param registration the registration.
     * @return its public view.
     */
    public ClientResponse toResponse(final ClientRegistration registration) {
        return new ClientResponse(registration.clientId(), registration.name(), registration.confidential(),
                registration.authMethods(), registration.grantTypes(), registration.redirectUris(),
                registration.scopes(), registration.requireProofKey(), registration.audiences(),
                registration.accessTokenTtl(), registration.refreshTokenTtl(), registration.accessTokenFormat(),
                registration.reuseRefreshTokens(), registration.postLogoutRedirectUris(),
                registration.requireConsent());
    }

    /**
     * Maps several registrations, keeping their order.
     *
     * @param registrations the registrations.
     * @return their public views.
     */
    public List<ClientResponse> toResponses(final List<ClientRegistration> registrations) {
        return registrations.stream().map(this::toResponse).toList();
    }

    /**
     * Maps a created client: its public view and, for a confidential one, its secret (shown only once).
     *
     * @param created the created client.
     * @return the answer to the creation.
     */
    public CreatedClientResponse toCreatedResponse(final CreatedClient created) {
        return new CreatedClientResponse(toResponse(created.registration()), created.clientSecret());
    }

    /**
     * Maps a rotated secret (shown only once).
     *
     * @param clientSecret the new secret in clear text.
     * @return the answer to the rotation.
     */
    public ClientSecretResponse toSecretResponse(final String clientSecret) {
        return new ClientSecretResponse(clientSecret);
    }
}
