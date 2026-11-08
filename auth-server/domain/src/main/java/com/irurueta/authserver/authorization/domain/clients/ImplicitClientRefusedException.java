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

package com.irurueta.authserver.authorization.domain.clients;

/**
 * A client with the legacy implicit grant was submitted through the administration API: only the demo client seeded
 * under the {@code legacy-implicit} profile may have that grant, so the implicit flow never reaches a deployment that
 * did not opt in to it.
 */
public class ImplicitClientRefusedException extends IllegalArgumentException {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param clientId identifier of the client.
     */
    public ImplicitClientRefusedException(final String clientId) {
        super("Client '" + clientId + "': the implicit grant type is reserved to the legacy demo client seeded under "
                + "the legacy-implicit profile");
    }
}
