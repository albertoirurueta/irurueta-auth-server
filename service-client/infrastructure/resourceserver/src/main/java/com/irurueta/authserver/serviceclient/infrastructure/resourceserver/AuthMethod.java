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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * How the service client authenticates at the token endpoint ({@code service-client.auth.method}).
 */
@Getter
@RequiredArgsConstructor
public enum AuthMethod {

    /** A shared secret in an HTTP Basic header. */
    CLIENT_SECRET_BASIC(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),

    /** An assertion signed with the client's private key (RFC 7523). */
    PRIVATE_KEY_JWT(ClientAuthenticationMethod.PRIVATE_KEY_JWT),

    /** Mutual TLS with a certificate issued by a certification authority the server trusts (RFC 8705). */
    TLS_CLIENT_AUTH(ClientAuthenticationMethod.TLS_CLIENT_AUTH),

    /** Mutual TLS with a self-signed certificate registered with the server (RFC 8705). */
    SELF_SIGNED_TLS_CLIENT_AUTH(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);

    /** The method as Spring Security names it. */
    private final ClientAuthenticationMethod clientAuthenticationMethod;

    /**
     * Tells whether the method is authenticated by the client certificate of the TLS connection.
     *
     * @return true for the two mutual TLS methods.
     */
    public boolean isMutualTls() {
        return this == TLS_CLIENT_AUTH || this == SELF_SIGNED_TLS_CLIENT_AUTH;
    }
}
