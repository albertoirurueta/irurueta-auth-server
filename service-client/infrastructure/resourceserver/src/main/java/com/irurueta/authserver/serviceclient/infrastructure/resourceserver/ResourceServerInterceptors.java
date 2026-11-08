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

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Component;

/**
 * Creates the interceptors that put the access token on the calls to the resource server: Spring Security's {@link
 * OAuth2ClientHttpRequestInterceptor} (bearer), or the DPoP one when {@code service-client.auth.dpop} is on. Either
 * way a call that ends up without a token is refused instead of sent.
 */
@Component
@RequiredArgsConstructor
public class ResourceServerInterceptors {

    /** Obtains and renews the access tokens. */
    private final OAuth2AuthorizedClientManager manager;

    /** Creates the DPoP proofs; absent unless DPoP is enabled. */
    private final ObjectProvider<DPoPProofs> dpopProofs;

    /**
     * Creates the interceptors of one client.
     *
     * @param registrationId registration of the OAuth2 client that obtains the token.
     * @param principal      principal the token is cached under; the CLI has no security context to read it from.
     * @return the interceptors, in the order they run.
     */
    public List<ClientHttpRequestInterceptor> create(final String registrationId, final Authentication principal) {
        final var proofs = dpopProofs.getIfAvailable();
        if (proofs != null) {
            return List.of(new DPoPClientHttpRequestInterceptor(manager, proofs, registrationId, principal));
        }
        final var interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
        interceptor.setClientRegistrationIdResolver(request -> registrationId);
        interceptor.setPrincipalResolver(request -> principal);
        return List.of(interceptor, (request, body, execution) -> {
            // The OAuth2 interceptor lets the call through when no authorized client came back; this one never does.
            if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
                throw new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                        "The service client has no access token", null), registrationId);
            }
            return execution.execute(request, body);
        });
    }
}
