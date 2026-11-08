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
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks the sign-in with external providers as the whole application wires it, with Google, Apple and GitHub
 * configured (Microsoft left out): the login page lists exactly the configured providers, the framework endpoint
 * sends the browser to each provider's authorization page with what that provider needs (the form post response mode
 * of Apple, the e-mail scope of GitHub), the callback of Apple, and only that one, is exempt from CSRF protection, and
 * an answer that does not match an authorization request is a failed sign-in. Every client id and secret, and the
 * Apple key, is generated at run time; nothing leaves the process. The exchange with a provider, the account linking
 * and the tokens are checked against fake providers in {@code SocialLoginIT} and its siblings.
 */
@PostgresIT
@AutoConfigureMockMvc
class SocialLoginConfigurationIT {

    /** Client id of Google, generated for the run. */
    private static final String GOOGLE_CLIENT_ID = "google-" + UUID.randomUUID();

    /** Client id of Apple, generated for the run. */
    private static final String APPLE_CLIENT_ID = "apple-" + UUID.randomUUID();

    /** Path of the login page. */
    private static final String LOGIN = "/login";

    /** Path that starts a sign-in with a provider. */
    private static final String AUTHORIZATION = "/oauth2/authorization/";

    /** Path that receives the answer of a provider. */
    private static final String CALLBACK = "/login/oauth2/code/";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Configures three providers with values generated for the run.
     *
     * @param registry registry of the properties of the context.
     * @throws GeneralSecurityException if the Apple key cannot be generated.
     */
    @DynamicPropertySource
    static void providers(final DynamicPropertyRegistry registry) throws GeneralSecurityException {
        final var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        final var key = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        registry.add("authserver.social.providers.google.client-id", () -> GOOGLE_CLIENT_ID);
        registry.add("authserver.social.providers.google.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.github.client-id", () -> "github-" + UUID.randomUUID());
        registry.add("authserver.social.providers.github.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.apple.client-id", () -> APPLE_CLIENT_ID);
        registry.add("authserver.social.providers.apple.team-id", () -> "TEAM123456");
        registry.add("authserver.social.providers.apple.key-id", () -> "KEY1234567");
        registry.add("authserver.social.providers.apple.private-key", () -> key);
    }

    /**
     * Pins the locale of the localized text the assertions read.
     */
    @BeforeEach
    void setUp() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    /**
     * Verifies that the login page lists the configured providers and not the others.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void loginPage_whenProvidersAreConfigured_listsExactlyThose() throws Exception {
        mockMvc.perform(get(LOGIN))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("href=\"" + AUTHORIZATION + "google\"")))
                .andExpect(content().string(containsString("href=\"" + AUTHORIZATION + "github\"")))
                .andExpect(content().string(containsString("href=\"" + AUTHORIZATION + "apple\"")))
                .andExpect(content().string(containsString("Sign in with Google")))
                .andExpect(content().string(not(containsString(AUTHORIZATION + "microsoft"))));
    }

    /**
     * Verifies that a sign-in with Google starts at Google's authorization page for the configured client.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorization_whenGoogle_redirectsToGoogleForTheConfiguredClient() throws Exception {
        mockMvc.perform(get(AUTHORIZATION + "google"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith("https://accounts.google.com/o/oauth2/v2/auth")))
                .andExpect(header().string("Location", containsString("client_id=" + GOOGLE_CLIENT_ID)))
                .andExpect(header().string("Location", containsString("state=")));
    }

    /**
     * Verifies that a sign-in with Apple asks for the response to be posted, which is what makes Apple hand over the
     * e-mail address.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorization_whenApple_asksForTheFormPostResponseMode() throws Exception {
        mockMvc.perform(get(AUTHORIZATION + "apple"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith("https://appleid.apple.com/auth/authorize")))
                .andExpect(header().string("Location", containsString("client_id=" + APPLE_CLIENT_ID)))
                .andExpect(header().string("Location", containsString("response_mode=form_post")));
    }

    /**
     * Verifies that a sign-in with GitHub asks for the scope that lets the server read the verified e-mail address, and
     * that the other providers are not asked to post their response.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorization_whenGitHub_asksForTheEmailScopeAndNoFormPost() throws Exception {
        mockMvc.perform(get(AUTHORIZATION + "github"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith("https://github.com/login/oauth/authorize")))
                .andExpect(header().string("Location", containsString("user:email")))
                .andExpect(header().string("Location",
                        not(containsString("response_mode"))));
    }

    /**
     * Verifies that a provider that is not configured is not a way in: the framework refuses the request and never
     * sends the browser to the provider.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorization_whenProviderIsNotConfigured_neverRedirectsToTheProvider() throws Exception {
        mockMvc.perform(get(AUTHORIZATION + "microsoft"))
                .andExpect(status().is5xxServerError())
                .andExpect(header().doesNotExist("Location"));
    }

    /**
     * Verifies that Apple's callback accepts a post without a CSRF token (Apple posts it from its own site) and that
     * an answer that matches no authorization request is a failed sign-in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void callback_whenApplePostsWithoutAuthorizationRequest_isAFailedSignInNotAForbiddenRequest() throws Exception {
        mockMvc.perform(post(CALLBACK + "apple").param("code", "c").param("state", "s"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", endsWith(LOGIN + "?error")));
    }

    /**
     * Verifies that the callbacks of the other providers keep the CSRF protection of the chain.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void callback_whenAnotherProviderPostsWithoutCsrfToken_isForbidden() throws Exception {
        mockMvc.perform(post(CALLBACK + "google").param("code", "c").param("state", "s"))
                .andExpect(status().isForbidden());
    }
}
