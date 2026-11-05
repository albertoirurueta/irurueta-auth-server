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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.irurueta.authserver.authorization.api.web.SecurityConfig;
import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.login.LoginController;
import com.irurueta.authserver.authorization.api.web.login.LoginMethodFragment;
import com.irurueta.authserver.authorization.infrastructure.keys.TemporaryJwkConfiguration;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks the security filter chains and the login page in a web slice, with the login extension points replaced
 * by Mockito mocks. It is an integration test because it starts a Spring context.
 */
@WebMvcTest(controllers = LoginController.class)
@Import({SecurityConfig.class, TemporaryJwkConfiguration.class, SecurityConfigIT.TestBeans.class})
class SecurityConfigIT {

    /** Username of the in-memory test user. */
    private static final String USERNAME = "u";

    /** Clear-text password of the in-memory test user; not a real credential. */
    private static final String PASSWORD = "p";

    /** Path of the endpoint that the first customizer permits. */
    private static final String CUSTOMIZER_PATH = "/test-method/**";

    /** Beans of the slice that are not mocks: real in-memory framework implementations used as test data. */
    @TestConfiguration(proxyBeanMethods = false)
    static class TestBeans {

        /**
         * Creates a repository holding one client.
         *
         * @return the repository.
         */
        @Bean
        RegisteredClientRepository registeredClientRepository() {
            return new InMemoryRegisteredClientRepository(RegisteredClient.withId("1").clientId("c")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://localhost/cb").build());
        }

        /**
         * Creates the default authorization server settings.
         *
         * @return the settings.
         */
        @Bean
        AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }

        /**
         * Creates the decoder of the tokens signed with the temporary key.
         *
         * @param jwkSource source of the signing keys.
         * @return the decoder.
         */
        @Bean
        JwtDecoder jwtDecoder(final JWKSource<SecurityContext> jwkSource) {
            return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        }

        /**
         * Creates a user store holding one user.
         *
         * @return the user store.
         */
        @Bean
        UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(
                    User.withUsername(USERNAME).password("{noop}" + PASSWORD).roles("USER").build());
        }

        /**
         * Creates the customizer that is applied second.
         *
         * @return a mock customizer.
         */
        @Bean
        @Order(2)
        LoginChainCustomizer secondCustomizer() {
            return mock(LoginChainCustomizer.class);
        }

        /**
         * Creates the customizer that is applied first and permits its own endpoint, as passkeys or one-time
         * tokens will.
         *
         * @return a mock customizer.
         */
        @Bean
        @Order(1)
        LoginChainCustomizer firstCustomizer() {
            final var customizer = mock(LoginChainCustomizer.class);
            doAnswer(invocation -> {
                final HttpSecurity http = invocation.getArgument(0);
                http.authorizeHttpRequests(authorize -> authorize.requestMatchers(CUSTOMIZER_PATH).permitAll());
                return null;
            }).when(customizer).customize(any(HttpSecurity.class));
            return customizer;
        }
    }

    /** MockMvc bound to the web slice. */
    @Autowired
    private MockMvc mockMvc;

    /** Customizer applied first. */
    @Autowired
    @Qualifier("firstCustomizer")
    private LoginChainCustomizer firstCustomizer;

    /** Customizer applied second. */
    @Autowired
    @Qualifier("secondCustomizer")
    private LoginChainCustomizer secondCustomizer;

    /** Fragment rendered by the login page. */
    @MockitoBean
    private LoginMethodFragment fragment;

    /**
     * Stubs the fragment so that the login page renders the first fragment of the test template.
     */
    @BeforeEach
    void stubFragment() {
        when(fragment.reference()).thenReturn("test-fragments :: first");
    }

    /**
     * Verifies that the discovery document is public.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void openIdConfiguration_whenRequestedAnonymously_isPublic() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").exists());
    }

    /**
     * Verifies that the JWK set is public.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void jwks_whenRequestedAnonymously_isPublic() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    /**
     * Verifies that the login page renders the form and the fragment of the authentication methods.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenRequested_rendersFormAndFragment() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("name=\"username\"")))
                .andExpect(content().string(containsString("first-method")))
                .andExpect(content().string(not(containsString("second-method"))));
    }

    /**
     * Verifies that a protected page redirects an anonymous request to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void protectedPage_whenRequestedAnonymously_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/account"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", endsWith("/login")));
    }

    /**
     * Verifies that the authorization endpoint redirects an anonymous request to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorizationEndpoint_whenRequestedAnonymously_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/oauth2/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb"
                        + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", endsWith("/login")));
    }

    /**
     * Verifies that a form login with valid credentials redirects.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenCredentialsAreValid_redirects() throws Exception {
        mockMvc.perform(post("/login").param("username", USERNAME).param("password", PASSWORD).with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    /**
     * Verifies that a form login with invalid credentials redirects to the error page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenCredentialsAreInvalid_redirectsToError() throws Exception {
        mockMvc.perform(post("/login").param("username", USERNAME).param("password", "x").with(csrf()))
                .andExpect(redirectedUrl("/login?error"));
    }

    /**
     * Verifies that a customizer can permit its own endpoints.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void customizer_whenItPermitsAnEndpoint_doesNotRedirectToLogin() throws Exception {
        // no controller handles the path: reaching the dispatcher (404) proves the request was not sent to login
        mockMvc.perform(get("/test-method/start"))
                .andExpect(status().isNotFound());
    }

    /**
     * Verifies that the customizers are applied in the order of their {@code @Order}.
     */
    @Test
    void customizers_whenChainIsBuilt_areAppliedInOrder() {
        final var order = inOrder(firstCustomizer, secondCustomizer);

        order.verify(firstCustomizer).customize(any(HttpSecurity.class));
        order.verify(secondCustomizer).customize(any(HttpSecurity.class));
    }
}
