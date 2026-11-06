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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.ConsentPageApi;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.RequestContextUtils;

/**
 * Serves the consent page the authorization endpoint redirects to when a client needs the user's approval, as the
 * contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes it through the generated
 * {@link ConsentPageApi}. It lives in this adapter because it works with the framework's
 * {@code RegisteredClientRepository} and {@code OAuth2AuthorizationConsentService}.
 */
@Controller
@RequiredArgsConstructor
public class ConsentController implements ConsentPageApi {

    /** Path of the consent page, and of its registration in the authorization endpoint, taken from the contract. */
    public static final String CONSENT_PATH = PATH_CONSENT_PAGE;

    /** Name of the consent template. */
    static final String VIEW_NAME = "consent";

    /** Name of the model attribute that holds the {@link ConsentPageModel}. */
    static final String CONSENT_ATTRIBUTE = "consent";

    /** Finds the client that asks for access. */
    private final RegisteredClientRepository registeredClientRepository;

    /** Finds the scopes the user granted earlier. */
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    /** Builds the view model. */
    private final ConsentPageModelMapper mapper;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, which carries the signed-in user and the locale. */
    private final HttpServletRequest request;

    // tag::consent-controller[]
    /**
     * Renders the consent page.
     *
     * @param clientId identifier of the client that asks for access.
     * @param scope    requested scopes, space delimited.
     * @param state    state of the authorization request.
     * @return the consent page.
     * @throws ResponseStatusException with status 400 when the client is unknown.
     */
    @Override
    public ResponseEntity<String> consentPage(final String clientId, final String scope, final String state) {
        final var client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown client");
        }
        final var principalName = request.getUserPrincipal().getName();
        final var consent = authorizationConsentService.findById(client.getId(), principalName);
        final Set<String> granted = consent == null ? Set.of() : consent.getScopes();
        return pageRenderer.render(VIEW_NAME, Map.of(CONSENT_ATTRIBUTE, mapper.toModel(client, principalName, state,
                scope, granted, RequestContextUtils.getLocale(request))));
    }
    // end::consent-controller[]
}
