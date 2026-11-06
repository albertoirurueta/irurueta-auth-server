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

package com.irurueta.authserver.authorization.api.web.consent;

import io.swagger.v3.oas.annotations.Hidden;
import java.security.Principal;
import java.util.Locale;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

/**
 * Serves the consent page the authorization endpoint redirects to when a client needs the user's approval. It
 * lives in this adapter because it works with the framework's {@code RegisteredClientRepository} and
 * {@code OAuth2AuthorizationConsentService}.
 */
// HTML page, not part of the OpenAPI contract
@Hidden
@Controller
@RequiredArgsConstructor
public class ConsentController {

    /** Path of the consent page, and of its registration in the authorization endpoint. */
    public static final String CONSENT_PATH = "/oauth2/consent";

    /** Name of the model attribute that holds the {@link ConsentPageModel}. */
    static final String CONSENT_ATTRIBUTE = "consent";

    /** Finds the client that asks for access. */
    private final RegisteredClientRepository registeredClientRepository;

    /** Finds the scopes the user granted earlier. */
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    /** Builds the view model. */
    private final ConsentPageModelMapper mapper;

    /**
     * Renders the consent page.
     *
     * @param principal signed-in user.
     * @param model     model of the view.
     * @param locale    locale of the request.
     * @param clientId  identifier of the client that asks for access.
     * @param scope     requested scopes, space delimited.
     * @param state     state of the authorization request.
     * @return the consent template name.
     * @throws ResponseStatusException with status 400 when the client is unknown.
     */
    @GetMapping(CONSENT_PATH)
    public String consent(
            final Principal principal, final Model model, final Locale locale,
            @RequestParam("client_id") final String clientId,
            @RequestParam("scope") final String scope,
            @RequestParam("state") final String state) {
        final var client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown client");
        }
        final var consent = authorizationConsentService.findById(client.getId(), principal.getName());
        final Set<String> granted = consent == null ? Set.of() : consent.getScopes();
        model.addAttribute(CONSENT_ATTRIBUTE, mapper.toModel(client, principal.getName(), state, scope, granted,
                locale));
        return "consent";
    }
}
