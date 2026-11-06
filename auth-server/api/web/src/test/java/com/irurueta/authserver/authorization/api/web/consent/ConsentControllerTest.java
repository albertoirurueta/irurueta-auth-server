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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.ui.ExtendedModelMap;
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

    /** Signed-in user. */
    @Mock
    private Principal principal;

    /** Controller under test. */
    @InjectMocks
    private ConsentController controller;

    /**
     * Verifies that the page is built from the client and from the scopes granted earlier.
     */
    @Test
    void consent_whenClientHadConsent_passesTheGrantedScopesToTheMapper() {
        final var client = client();
        final var consent = OAuth2AuthorizationConsent.withId(client.getId(), PRINCIPAL).scope("profile").build();
        final var page = new ConsentPageModel(CLIENT_ID, "App", PRINCIPAL, STATE, List.of(),
                List.of());
        when(principal.getName()).thenReturn(PRINCIPAL);
        when(clients.findByClientId(CLIENT_ID)).thenReturn(client);
        when(consents.findById(client.getId(), PRINCIPAL)).thenReturn(consent);
        when(mapper.toModel(client, PRINCIPAL, STATE, SCOPE, Set.of("profile"), Locale.ENGLISH)).thenReturn(page);
        final var model = new ExtendedModelMap();

        final var view = controller.consent(principal, model, Locale.ENGLISH, CLIENT_ID, SCOPE, STATE);

        assertEquals("consent", view);
        assertSame(page, model.get(ConsentController.CONSENT_ATTRIBUTE));
    }

    /**
     * Verifies that a first consent has no scope granted earlier.
     */
    @Test
    void consent_whenClientHadNoConsent_passesNoGrantedScope() {
        final var client = client();
        when(principal.getName()).thenReturn(PRINCIPAL);
        when(clients.findByClientId(CLIENT_ID)).thenReturn(client);

        controller.consent(principal, new ExtendedModelMap(), Locale.ENGLISH, CLIENT_ID, SCOPE, STATE);

        verify(mapper).toModel(client, PRINCIPAL, STATE, SCOPE, Set.of(), Locale.ENGLISH);
    }

    /**
     * Verifies that an unknown client is a bad request.
     */
    @Test
    void consent_whenClientIsUnknown_throwsBadRequest() {
        final var model = new ExtendedModelMap();

        final var error = assertThrows(ResponseStatusException.class,
                () -> controller.consent(principal, model, Locale.ENGLISH, CLIENT_ID, SCOPE, STATE));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
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
