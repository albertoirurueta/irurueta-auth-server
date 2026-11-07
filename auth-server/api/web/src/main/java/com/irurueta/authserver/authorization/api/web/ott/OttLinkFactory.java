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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Builds the magic link of a token. It points at the confirmation page ({@code GET /login/ott/confirm}), whose button
 * posts the token, and never at an endpoint that consumes it, so a mail scanner that opens the link does not use it
 * up. The host is the configured issuer of this server, never the {@code Host} header of the request that asked for the
 * link, which an attacker controls: a link built from it could carry the token of somebody else to another host.
 */
@Component
public class OttLinkFactory {

    /** Name of the query parameter that carries the token. */
    public static final String TOKEN_PARAMETER = "token";

    /** Public base URL of this server, the issuer of the tokens. */
    private final String issuer;

    /**
     * Creates the factory.
     *
     * @param issuer issuer of this server ({@code spring.security.oauth2.authorizationserver.issuer}).
     */
    public OttLinkFactory(@Value("${spring.security.oauth2.authorizationserver.issuer}") final String issuer) {
        this.issuer = issuer;
    }

    /**
     * Builds the link of a token.
     *
     * @param tokenValue value of the token.
     * @return the link to the confirmation page.
     */
    public URI confirmationLink(final String tokenValue) {
        return UriComponentsBuilder.fromUriString(issuer)
                .path(OneTimeTokenPageApi.PATH_OTT_CONFIRM_PAGE)
                .queryParam(TOKEN_PARAMETER, tokenValue)
                .build()
                .toUri();
    }
}
