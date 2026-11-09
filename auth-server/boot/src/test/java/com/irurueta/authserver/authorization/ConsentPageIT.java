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

package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Drives the authorization endpoint of the running application up to the consent page and answers it: the page is
 * rendered from the registered client, a denial returns {@code access_denied} to the client and an approval returns
 * the authorization code.
 */
@PostgresIT
@AutoConfigureMockMvc
class ConsentPageIT {

    /** State of the authorization requests. */
    private static final String STATE = "xyz";

    /** Authorization endpoint. */
    private static final String AUTHORIZE_PATH = "/oauth2/authorize";

    /** Name of the parameter that carries the client identifier. */
    private static final String CLIENT_ID_PARAM = "client_id";

    /** Name of the parameter that carries the state. */
    private static final String STATE_PARAM = "state";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Repository where the test client, which requires consent, is stored. */
    @Autowired
    private RegisteredClientRepository clients;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Builds the users. */
    private AuthServerFixtures fixtures;

    /** Browser session of the signed-in user. */
    private MockHttpSession session;

    /** Identifier of the client that requires consent. */
    private String clientId;

    /** Location of the consent page the authorization endpoint redirected to. */
    private URI consentPage;

    /** State the authorization endpoint generated for the consent step, which the decision must post back. */
    private String consentState;

    /**
     * Registers a client that requires consent and signs a user in up to the consent redirect.
     *
     * @throws Exception if a request cannot be performed.
     */
    @BeforeEach
    void startAuthorization() throws Exception {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        final var user = fixtures.createUser();
        clientId = "client-" + UUID.randomUUID();
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName("Consent test app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(AuthServerFixtures.REDIRECT_URI)
                .scope("openid").scope("profile")
                .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(true)
                        .build())
                .build());
        final var authorizeUri = UriComponentsBuilder.fromPath(AUTHORIZE_PATH)
                .queryParam("response_type", "code")
                .queryParam(CLIENT_ID_PARAM, clientId)
                .queryParam("redirect_uri", AuthServerFixtures.REDIRECT_URI)
                .queryParam("scope", "openid profile")
                .queryParam(STATE_PARAM, STATE)
                .queryParam("code_challenge", AuthServerFixtures.s256(AuthServerFixtures.randomValue()))
                .queryParam("code_challenge_method", "S256")
                .build().toUriString();

        session = new MockHttpSession();
        mockMvc.perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());
        mockMvc.perform(post("/login").session(session).with(csrf())
                        .param("username", user.username()).param("password", user.credential()))
                .andExpect(status().is3xxRedirection());
        final var redirect = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/oauth2/consent"))).andReturn()
                .getResponse().getRedirectedUrl();
        assertNotNull(redirect);
        consentPage = URI.create(redirect);
        consentState = UriUtils.decode(
                UriComponentsBuilder.fromUri(consentPage).build().getQueryParams().getFirst(STATE_PARAM),
                StandardCharsets.UTF_8);
    }

    /**
     * Verifies that the consent page names the client, describes the scope to approve and offers both decisions.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void consentPage_whenClientRequiresConsent_listsTheScopeAndBothDecisions() throws Exception {
        mockMvc.perform(get(consentPage).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Consent test app")))
                .andExpect(content().string(containsString("Read your profile")))
                .andExpect(content().string(containsString("value=\"profile\"")))
                .andExpect(content().string(containsString("id=\"allow\"")))
                .andExpect(content().string(containsString("id=\"deny\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    /**
     * Verifies that denying the consent, which posts no scope, returns {@code access_denied} to the client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void consentDecision_whenUserDenies_redirectsWithAccessDenied() throws Exception {
        mockMvc.perform(post(AUTHORIZE_PATH).session(session).with(csrf())
                        .param(CLIENT_ID_PARAM, clientId).param(STATE_PARAM, consentState))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(AuthServerFixtures.REDIRECT_URI)))
                .andExpect(header().string("Location", containsString("error=access_denied")))
                .andExpect(header().string("Location", containsString("state=" + STATE)));
    }

    // tag::consent-page-it[]
    /**
     * Verifies that approving the scope returns the authorization code.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void consentDecision_whenUserAllows_redirectsWithTheCode() throws Exception {
        mockMvc.perform(post(AUTHORIZE_PATH).session(session).with(csrf())
                        .param(CLIENT_ID_PARAM, clientId).param(STATE_PARAM, consentState).param("scope", "profile"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(AuthServerFixtures.REDIRECT_URI + "?code=")));
    }
    // end::consent-page-it[]
}
