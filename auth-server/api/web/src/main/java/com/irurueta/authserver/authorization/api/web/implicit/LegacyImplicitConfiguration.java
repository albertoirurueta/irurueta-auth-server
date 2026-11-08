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
package com.irurueta.authserver.authorization.api.web.implicit;

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// tag::implicit-chain-config[]
/**
 * Enables the legacy implicit flow. It exists only under the {@code legacy-implicit} profile, as a demonstration of the
 * risks that made OAuth 2.1 remove it, and never in a deployment: the authorization endpoint accepts
 * {@code response_type=token} for one client, the client is seeded, and a demo page is served.
 */
@Profile(LegacyImplicitConfiguration.PROFILE)
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LegacyImplicitProperties.class)
public class LegacyImplicitConfiguration implements WebMvcConfigurer {

    /** Name of the profile that enables the flow. */
    public static final String PROFILE = "legacy-implicit";

    /** Path of the demo page and its script. */
    public static final String DEMO_PATH = "/legacy-implicit/";

    /** Order of the customizer of the login chain that opens the demo page, after the existing ones. */
    public static final int LOGIN_CUSTOMIZER_ORDER = 8;

    /** Location of the demo page and its script in the classpath. */
    private static final String DEMO_LOCATION = "classpath:/legacy-implicit/";

    /**
     * Declares the factory of the token generator of the flow.
     *
     * @param jwtEncoder        signs the self-contained tokens.
     * @param jwtCustomizers    adds the claims of the other flows to a JWT.
     * @param claimsCustomizers adds the claims of the other flows to a reference token.
     * @return the factory.
     */
    @Bean
    public LegacyImplicitTokenGeneratorFactory legacyImplicitTokenGeneratorFactory(final JwtEncoder jwtEncoder,
            final ObjectProvider<OAuth2TokenCustomizer<JwtEncodingContext>> jwtCustomizers,
            final ObjectProvider<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>> claimsCustomizers) {
        return new LegacyImplicitTokenGeneratorFactory(jwtEncoder, jwtCustomizers, claimsCustomizers);
    }

    /**
     * Declares the customizer that adds the flow to the authorization endpoint.
     *
     * @param registeredClients    finds the client.
     * @param authorizationService stores the authorization behind the token.
     * @param generatorFactory     builds the token generator.
     * @param serverSettings       settings of the protocol endpoints, for the authorization endpoint.
     * @param authorizationManager applies the multi-factor policy.
     * @param properties           settings of the flow.
     * @return the customizer.
     */
    @Bean
    @Order(LegacyImplicitProtocolChainCustomizer.ORDER)
    public ProtocolChainCustomizer legacyImplicitProtocolChainCustomizer(
            final RegisteredClientRepository registeredClients, final OAuth2AuthorizationService authorizationService,
            final LegacyImplicitTokenGeneratorFactory generatorFactory,
            final AuthorizationServerSettings serverSettings, final MfaAuthorizationManager authorizationManager,
            final LegacyImplicitProperties properties) {
        return new LegacyImplicitProtocolChainCustomizer(
                new LegacyImplicitAuthorizationRequestConverter(properties.clientId(),
                        serverSettings.getAuthorizationEndpoint()),
                new LegacyImplicitAuthenticationProvider(registeredClients, authorizationService,
                        generatorFactory.create(), authorizationManager, LegacyImplicitProperties.MAX_ACCESS_TOKEN_TTL),
                new LegacyImplicitResponseHandler(new AuthorizationCodeResponseHandler()));
    }

    /**
     * Declares the seeder of the client of the flow.
     *
     * @param seedRegisteredClientsUseCase seeds the clients.
     * @param properties                   settings of the flow.
     * @return the seeder.
     */
    @Bean
    public LegacyImplicitClientSeeder legacyImplicitClientSeeder(
            final SeedRegisteredClientsUseCase seedRegisteredClientsUseCase,
            final LegacyImplicitProperties properties) {
        return new LegacyImplicitClientSeeder(seedRegisteredClientsUseCase, properties);
    }

    /**
     * Declares the customizer of the login chain that opens the demo page and its script, which are static files
     * that a browser fetches before anybody has signed in.
     *
     * @return the customizer.
     */
    @Bean
    @Order(LOGIN_CUSTOMIZER_ORDER)
    public LoginChainCustomizer legacyImplicitLoginChainCustomizer() {
        return http -> http.authorizeHttpRequests(authorize -> authorize.requestMatchers(DEMO_PATH + "**").permitAll());
    }

    /**
     * Serves the demo page and its script from the classpath.
     *
     * @param registry the registry of resource handlers.
     */
    @Override
    public void addResourceHandlers(final ResourceHandlerRegistry registry) {
        registry.addResourceHandler(DEMO_PATH + "**").addResourceLocations(DEMO_LOCATION);
    }

    /**
     * Serves the demo page at the directory path.
     *
     * @param registry the registry of view controllers.
     */
    @Override
    public void addViewControllers(final ViewControllerRegistry registry) {
        registry.addViewController(DEMO_PATH).setViewName("forward:" + DEMO_PATH + "index.html");
    }
}
// end::implicit-chain-config[]
