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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Creates the DPoP proofs (RFC 9449) of the service client. Spring Security has no client-side DPoP support, so the
 * proofs are made with Nimbus' {@link DPoPProofFactory}, signed with a key pair that lives as long as the process.
 */
@RequiredArgsConstructor
public class DPoPProofs {

    /** Creates and signs the proofs. */
    private final DPoPProofFactory proofFactory;

    /**
     * Creates the proof of a token request: it binds the request, not yet any token.
     *
     * @param method HTTP method of the request.
     * @param uri    URI of the request.
     * @return the serialized proof JWT.
     * @throws IllegalStateException if the proof cannot be signed.
     */
    public String proof(final String method, final URI uri) {
        try {
            return proofFactory.createDPoPJWT(method, withoutQuery(uri)).serialize();
        } catch (final JOSEException e) {
            throw new IllegalStateException("The DPoP proof cannot be signed", e);
        }
    }

    /**
     * Creates the proof of a call that carries an access token: it also binds the token ({@code ath} claim).
     *
     * @param method      HTTP method of the request.
     * @param uri         URI of the request.
     * @param accessToken value of the access token the request carries.
     * @return the serialized proof JWT.
     * @throws IllegalStateException if the proof cannot be signed.
     */
    public String proof(final String method, final URI uri, final String accessToken) {
        try {
            return proofFactory.createDPoPJWT(method, withoutQuery(uri), new DPoPAccessToken(accessToken))
                    .serialize();
        } catch (final JOSEException e) {
            throw new IllegalStateException("The DPoP proof cannot be signed", e);
        }
    }

    /**
     * Removes the query and the fragment, which {@code htu} does not include.
     *
     * @param uri the URI of the request.
     * @return the URI as the proof states it.
     */
    private static URI withoutQuery(final URI uri) {
        return UriComponentsBuilder.fromUri(uri).replaceQuery(null).fragment(null).build().toUri();
    }
}
