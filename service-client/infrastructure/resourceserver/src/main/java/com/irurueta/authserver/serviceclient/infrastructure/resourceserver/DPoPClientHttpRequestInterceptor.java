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

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Sends the access token of an authorized client as {@code Authorization: DPoP <token>} together with a {@code DPoP}
 * proof that binds the request and the token, when the token is DPoP-bound. Spring Security's own interceptor can
 * only set a bearer header, so this one replaces it when DPoP is enabled. A call without a token is never sent.
 */
@RequiredArgsConstructor
public class DPoPClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    /** Name of the header that carries the proof. */
    public static final String DPOP_HEADER = "DPoP";

    /** Scheme of a DPoP-bound token in the {@code Authorization} header. */
    private static final String DPOP_SCHEME = "DPoP ";

    /** Obtains (and renews) the access token. */
    private final OAuth2AuthorizedClientManager manager;

    /** Creates the proofs. */
    private final DPoPProofs proofs;

    /** Registration of the client that obtains the token. */
    private final String registrationId;

    /** Principal the token is cached under. */
    private final Authentication principal;

    // tag::dpop-client[]
    @Override
    public ClientHttpResponse intercept(final HttpRequest request, final byte[] body,
            final ClientHttpRequestExecution execution) throws IOException {
        final var authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
                .principal(principal)
                .build();
        final var authorizedClient = manager.authorize(authorizeRequest);
        if (authorizedClient == null) {
            throw new ClientAuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                    "The service client has no access token", null), registrationId);
        }
        final var token = authorizedClient.getAccessToken();
        if (OAuth2AccessToken.TokenType.DPOP.equals(token.getTokenType())) {
            request.getHeaders().set(HttpHeaders.AUTHORIZATION, DPOP_SCHEME + token.getTokenValue());
            request.getHeaders().set(DPOP_HEADER,
                    proofs.proof(request.getMethod().name(), request.getURI(), token.getTokenValue()));
        } else {
            request.getHeaders().setBearerAuth(token.getTokenValue());
        }
        return execution.execute(request, body);
    }
    // end::dpop-client[]
}
