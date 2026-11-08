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
package com.irurueta.authserver.authorization.api.web.implicit;

import java.util.Map;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * The request of a public client of the device flow to be authenticated by its identifier alone. It is a type of its
 * own so that {@link DeviceClientAuthenticationProvider} only ever accepts what {@link
 * DeviceClientAuthenticationConverter} produced: a token with the same authentication method that another converter
 * built from request parameters (the PKCE one) must still be verified with its code verifier.
 */
public class DeviceClientAuthenticationToken extends OAuth2ClientAuthenticationToken {

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** Identifier of the public client. */
    private final String clientId;

    /**
     * Creates the request.
     *
     * @param clientId identifier of the public client.
     */
    public DeviceClientAuthenticationToken(final String clientId) {
        super(clientId, ClientAuthenticationMethod.NONE, null, Map.of());
        this.clientId = clientId;
    }

    /**
     * Tells the client that asks to be authenticated.
     *
     * @return the identifier of the public client.
     */
    public String clientId() {
        return clientId;
    }
}
