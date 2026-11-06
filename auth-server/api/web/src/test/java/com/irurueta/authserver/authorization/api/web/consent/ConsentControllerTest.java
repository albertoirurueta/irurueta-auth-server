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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests of {@link ConsentController}.
 */
@ExtendWith(MockitoExtension.class)
class ConsentControllerTest {

    /** Identifier of the test client. */
    private static final String CLIENT_ID = "app";

    /** Name of the test user. */
    private static final String PRINCIPAL = "demo";

    /** State of the authorization request. */
    private static final String STATE = "xyz";

    /** Scopes of the authorization request. */
    private static final String SCOPE = "openid profile";

    /** Finds the client. */
    @Mock
    private RegisteredClientRepository clients;

    /** Finds the earlier consent. */
    @Mock
    private OAuth2AuthorizationConsentService consents;

    /** Builds the view model. */
    @Mock
    private ConsentPageModelMapper mapper;

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** The current request. */
    @Mock
    private HttpServletRequest request;

    /** Signed-in user. */
    @Mock
    private Principal principal;

    /** Controller under test. */
    @InjectMocks
    private ConsentController controller;

    /**
     * Verifies that the page is built from the client and from the scopes granted earlier, in the locale of the
     * request.
     */
    @Test
    void consentPage_whenClientHadConsent_passesTheGrantedScopesToTheMapper() {
        final var client = client();
        final var consent = OAuth2AuthorizationConsent.withId(client.getId(), PRINCIPAL).scope("profile").build();
        final var model = new ConsentPageModel(CLIENT_ID, "App", PRINCIPAL, STATE, List.of(), List.of());
        final var page = ResponseEntity.ok("<html></html>");
        signIn();
        when(clients.findByClientId(CLIENT_ID)).thenReturn(client);
        when(consents.findById(client.getId(), PRINCIPAL)).thenReturn(consent);
        when(mapper.toModel(client, PRINCIPAL, STATE, SCOPE, Set.of("profile"), Locale.ENGLISH)).thenReturn(model);
        when(pageRenderer.render(ConsentController.VIEW_NAME, Map.of(ConsentController.CONSENT_ATTRIBUTE, model)))
                .thenReturn(page);

        assertSame(page, controller.consentPage(CLIENT_ID, SCOPE, STATE));
    }

    /**
     * Verifies that a first consent has no scope granted earlier.
     */
    @Test
    void consentPage_whenClientHadNoConsent_passesNoGrantedScope() {
        final var client = client();
        signIn();
        when(clients.findByClientId(CLIENT_ID)).thenReturn(client);
        when(mapper.toModel(any(), any(), any(), any(), any(), any()))
                .thenReturn(new ConsentPageModel(CLIENT_ID, "App", PRINCIPAL, STATE, List.of(), List.of()));

        controller.consentPage(CLIENT_ID, SCOPE, STATE);

        verify(mapper).toModel(client, PRINCIPAL, STATE, SCOPE, Set.of(), Locale.ENGLISH);
    }

    /**
     * Verifies that an unknown client is a bad request.
     */
    @Test
    void consentPage_whenClientIsUnknown_throwsBadRequest() {
        final var error = assertThrows(ResponseStatusException.class,
                () -> controller.consentPage(CLIENT_ID, SCOPE, STATE));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
    }

    /**
     * Makes the request carry the signed-in user and the English locale.
     */
    private void signIn() {
        when(principal.getName()).thenReturn(PRINCIPAL);
        when(request.getUserPrincipal()).thenReturn(principal);
        when(request.getLocale()).thenReturn(Locale.ENGLISH);
    }

    /**
     * Builds the test client.
     *
     * @return the client.
     */
    private static RegisteredClient client() {
        return RegisteredClient.withId("1").clientId(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://app.example.test/callback").build();
    }
}
