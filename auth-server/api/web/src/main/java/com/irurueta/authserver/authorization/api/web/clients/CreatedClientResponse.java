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

import com.irurueta.authserver.authorization.application.clients.CreatedClient;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Answer to a client creation: the client and, for a confidential one, its secret. This is the only time the secret
 * is shown, so it is left out of {@link #toString()}.
 *
 * @param client       the created client.
 * @param clientSecret the generated secret, or {@code null} for a public client.
 */
@Schema(description = "The created client; the secret is shown only once")
public record CreatedClientResponse(ClientResponse client, String clientSecret) {

    /**
     * Maps a created client.
     *
     * @param created the created client.
     * @return its response.
     */
    public static CreatedClientResponse from(final CreatedClient created) {
        return new CreatedClientResponse(ClientResponse.from(created.registration()), created.clientSecret());
    }

    @Override
    public String toString() {
        return "CreatedClientResponse[client=" + client + "]";
    }
}
