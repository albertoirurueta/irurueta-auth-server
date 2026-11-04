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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.irurueta.authserver.authorization.keys.TemporaryJwkConfiguration;
import com.irurueta.authserver.authorization.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.login.LoginController;
import com.irurueta.authserver.authorization.login.LoginMethodFragment;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
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
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = LoginController.class)
@Import({SecurityConfig.class, TemporaryJwkConfiguration.class, SecurityConfigTest.TestBeans.class})
class SecurityConfigTest {

    @TestConfiguration(proxyBeanMethods = false)
    static class TestBeans {

        static final List<String> CALLS = new ArrayList<>();

        @Bean
        RegisteredClientRepository registeredClientRepository() {
            return new InMemoryRegisteredClientRepository(RegisteredClient.withId("1").clientId("c")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/cb").build());
        }

        @Bean
        AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
        }

        @Bean
        JwtDecoder jwtDecoder(final JWKSource<SecurityContext> jwkSource) {
            return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        }

        @Bean
        UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(User.withUsername("u").password("{noop}p").roles("USER").build());
        }

        @Bean
        @Order(2)
        LoginChainCustomizer secondCustomizer() {
            return http -> CALLS.add("second");
        }

        @Bean
        @Order(1)
        LoginChainCustomizer firstCustomizer() {
            return http -> {
                CALLS.add("first");
                // a login method permitting its own endpoints, as passkeys or one-time tokens will
                http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/test-method/**").permitAll());
            };
        }

        @Bean
        LoginMethodFragment fragment() {
            return new LoginMethodFragment() {
                @Override
                public String templateName() {
                    return "test-fragments";
                }

                @Override
                public String fragmentName() {
                    return "first";
                }

                @Override
                public int order() {
                    return 1;
                }
            };
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void openIdConfiguration_isPublic() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").exists());
    }

    @Test
    void jwks_isPublic() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    @Test
    void login_rendersFormAndFragment() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("name=\"username\"")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("first-method")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("second-method"))));
    }

    @Test
    void protectedPage_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/account"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.endsWith("/login")));
    }

    @Test
    void authorizationEndpoint_redirectsAnonymousToLogin() throws Exception {
        mockMvc.perform(get("/oauth2/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.endsWith("/login")));
    }

    @Test
    void formLogin_withValidCredentials_redirects() throws Exception {
        mockMvc.perform(post("/login").param("username", "u").param("password", "p").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void formLogin_withInvalidCredentials_redirectsToError() throws Exception {
        mockMvc.perform(post("/login").param("username", "u").param("password", "x").with(csrf()))
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void customizer_canPermitItsOwnEndpoints() throws Exception {
        // no controller handles the path: reaching the dispatcher (404) proves the request was not sent to login
        mockMvc.perform(get("/test-method/start"))
                .andExpect(status().isNotFound());
    }

    @Test
    void customizers_areAppliedInOrder() {
        assertThat(TestBeans.CALLS).startsWith("first", "second");
    }
}
