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
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Drives the device authorization grant (RFC 8628) through the running application: the device asks for its codes, the
 * user signs in, types the code on the verification page, approves the consent on the consent page, and the device
 * obtains its tokens. A wrong code goes back to the page with an error, and a user whose account (or whose device's
 * client) requires a second factor is sent to the second-factor page instead of approving the device.
 */
@PostgresIT
@AutoConfigureMockMvc
class DeviceVerificationPageIT {

    /** Path of the device authorization endpoint. */
    private static final String DEVICE_AUTHORIZATION = "/oauth2/device_authorization";

    /** Path of the verification endpoint and page. */
    private static final String VERIFICATION = "/oauth2/device_verification";

    /** Name of the parameter that carries the client identifier. */
    private static final String CLIENT_ID_PARAM = "client_id";

    /** Name of the parameter that carries the user code. */
    private static final String USER_CODE_PARAM = "user_code";

    /** Name of the parameter that carries the state of the consent step. */
    private static final String STATE_PARAM = "state";

    /** Name of the response header with the location of a redirect. */
    private static final String LOCATION = "Location";

    /** Grant type of the device flow. */
    private static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /** Lifetime of the access tokens of the client. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(10);

    /** Lifetime of the refresh tokens of the client. */
    private static final Duration REFRESH_TTL = Duration.ofHours(1);

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Port that stores the per-user multi-factor settings. */
    @Autowired
    private UserMfaSettingsRepository mfaSettings;

    /** Builds the users. */
    private AuthServerFixtures fixtures;

    /** The user who approves the device. */
    private AuthServerFixtures.TestUser user;

    /** Identifier of the public client of the device. */
    private String clientId;

    /**
     * Registers a public client of the device grant and a user.
     */
    @BeforeEach
    void registerDeviceClient() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        user = fixtures.createUser();
        clientId = "device-" + UUID.randomUUID();
        clientRegistrations.save(new ClientRegistration(clientId, "Device test app", false, List.of("none"),
                List.of(DEVICE_GRANT), List.of(), List.of("profile", "documents.read"), true,
                List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE), TOKEN_TTL, REFRESH_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), true, false,
                null, null, null, null, false), null);
    }

    /**
     * Verifies that a visitor who has not signed in is sent to the sign-in page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerificationPage_whenNobodyIsSignedIn_redirectsToTheLoginPage() throws Exception {
        mockMvc.perform(get(VERIFICATION))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith("/login")));
    }

    /**
     * Verifies that the page offers the form that posts the code to the framework's endpoint, with the CSRF token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerificationPage_whenSignedIn_rendersTheForm() throws Exception {
        final var session = signIn();

        mockMvc.perform(get(VERIFICATION).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("action=\"/oauth2/device_verification\"")))
                .andExpect(content().string(containsString("name=\"user_code\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(not(containsString("That code is not valid"))));
    }

    /**
     * Verifies that a failed attempt is announced without saying why.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerificationPage_whenTheAttemptFailed_showsTheError() throws Exception {
        mockMvc.perform(get(VERIFICATION).queryParam("error", "").session(signIn()))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("That code is not valid")));
    }

    /**
     * Verifies that an approved device is told so.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerificationPage_whenTheDeviceWasApproved_showsTheConfirmation() throws Exception {
        mockMvc.perform(get(VERIFICATION).queryParam("success", "").session(signIn()))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("The device may continue now")))
                .andExpect(content().string(not(containsString("name=\"user_code\""))));
    }

    /**
     * Verifies the whole flow: the device waits, the user approves on the consent page, and the device gets tokens.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceFlow_whenTheUserApproves_theDeviceObtainsTokens() throws Exception {
        final var authorization = AuthServerFixtures.parse(mockMvc.perform(post(DEVICE_AUTHORIZATION)
                        .param(CLIENT_ID_PARAM, clientId).param("scope", "profile"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verification_uri", endsWith(VERIFICATION)))
                .andExpect(jsonPath("$.verification_uri_complete", containsString(VERIFICATION + "?user_code=")))
                .andReturn().getResponse().getContentAsString());
        final var deviceCode = authorization.get("device_code").asString();
        final var userCode = authorization.get(USER_CODE_PARAM).asString();
        mockMvc.perform(tokenRequest(deviceCode))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("authorization_pending"));
        final var session = signIn();

        final var consent = mockMvc.perform(post(VERIFICATION).session(session).with(csrf())
                        .param(USER_CODE_PARAM, userCode))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, containsString("/oauth2/consent?")))
                .andReturn().getResponse().getRedirectedUrl();
        assertNotNull(consent);
        final var consentUri = UriComponentsBuilder.fromUri(URI.create(consent)).build();
        final var state = UriUtils.decode(consentUri.getQueryParams().getFirst(STATE_PARAM),
                StandardCharsets.UTF_8);
        assertEquals(userCode, consentUri.getQueryParams().getFirst(USER_CODE_PARAM));
        mockMvc.perform(get(URI.create(consent)).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Device test app")))
                .andExpect(content().string(containsString("action=\"/oauth2/device_verification\"")))
                .andExpect(content().string(containsString("name=\"user_code\" value=\"" + userCode + "\"")));
        mockMvc.perform(post(VERIFICATION).session(session).with(csrf())
                        .param(CLIENT_ID_PARAM, clientId).param(STATE_PARAM, state).param(USER_CODE_PARAM, userCode)
                        .param("scope", "profile"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(VERIFICATION + "?success")));

        mockMvc.perform(tokenRequest(deviceCode))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    /**
     * Verifies that a code nobody was issued goes back to the page with an error.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerification_whenTheCodeIsUnknown_redirectsToThePageWithError() throws Exception {
        mockMvc.perform(post(VERIFICATION).session(signIn()).with(csrf()).param(USER_CODE_PARAM, "ZZZZ-ZZZZ"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith(VERIFICATION + "?error")));
    }

    /**
     * Verifies that a request that carries the code, as the complete verification URI does, is verified by the
     * endpoint straight away.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerification_whenTheLinkCarriesTheCode_goesStraightToTheConsentPage() throws Exception {
        final var authorization = AuthServerFixtures.parse(mockMvc.perform(post(DEVICE_AUTHORIZATION)
                        .param(CLIENT_ID_PARAM, clientId).param("scope", "profile"))
                .andReturn().getResponse().getContentAsString());

        mockMvc.perform(get(VERIFICATION + "?user_code=" + authorization.get(USER_CODE_PARAM).asString())
                        .session(signIn()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, containsString("/oauth2/consent?")));
    }

    /**
     * Verifies that a user whose account requires a second factor is sent to the second-factor page and does not
     * approve the device with a password alone.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerification_whenTheAccountRequiresASecondFactor_redirectsToTheSecondFactorPage() throws Exception {
        mfaSettings.setRequired(userAccounts.findByUsername(user.username()).orElseThrow().id(), true);

        mockMvc.perform(post(VERIFICATION).session(signIn()).with(csrf()).param(USER_CODE_PARAM, "ZZZZ-ZZZZ"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith("/login/second-factor")));
    }

    /**
     * Verifies that the multi-factor requirement of the device's client applies to the user code alone: the client
     * skips the consent page, so the post of the code (which names no client) is the approval, and a session that only
     * presented a password is sent to the second-factor page; the device is still waiting afterwards.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void deviceVerification_whenTheClientRequiresMfaWithoutConsent_redirectsToTheSecondFactorPage() throws Exception {
        final var mfaClientId = "device-mfa-" + UUID.randomUUID();
        clientRegistrations.save(new ClientRegistration(mfaClientId, "Device MFA app", false, List.of("none"),
                List.of(DEVICE_GRANT), List.of(), List.of("profile"), true,
                List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE), TOKEN_TTL, REFRESH_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, true,
                null, null, null, null, false), null);
        final var authorization = AuthServerFixtures.parse(mockMvc.perform(post(DEVICE_AUTHORIZATION)
                        .param(CLIENT_ID_PARAM, mfaClientId).param("scope", "profile"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        mockMvc.perform(post(VERIFICATION).session(signIn()).with(csrf())
                        .param(USER_CODE_PARAM, authorization.get(USER_CODE_PARAM).asString()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string(LOCATION, endsWith("/login/second-factor")));

        mockMvc.perform(post(AuthServerFixtures.TOKEN_PATH).param(AuthServerFixtures.GRANT_TYPE, DEVICE_GRANT)
                        .param("device_code", authorization.get("device_code").asString())
                        .param(CLIENT_ID_PARAM, mfaClientId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("authorization_pending"));
    }

    /**
     * Builds the poll of the device.
     *
     * @param deviceCode the device code.
     * @return the request.
     */
    private MockHttpServletRequestBuilder tokenRequest(
            final String deviceCode) {
        return post(AuthServerFixtures.TOKEN_PATH).param(AuthServerFixtures.GRANT_TYPE, DEVICE_GRANT)
                .param("device_code", deviceCode).param(CLIENT_ID_PARAM, clientId);
    }

    /**
     * Signs the user in.
     *
     * @return the session of the signed-in user.
     * @throws Exception if a request cannot be performed.
     */
    private MockHttpSession signIn() throws Exception {
        final var session = new MockHttpSession();
        mockMvc.perform(post("/login").session(session).with(csrf())
                        .param("username", user.username()).param("password", user.credential()))
                .andExpect(status().is3xxRedirection());
        return session;
    }
}
