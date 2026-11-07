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

package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.passkeys.AccountStatusUserDetailsService;
import com.irurueta.authserver.authorization.application.social.ResolveFederatedLoginUseCase;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.web.client.RestClient;

/**
 * Installs the sign-in with external providers in the login/UI chain. Nothing outside this feature is edited: the chain
 * applies every {@link LoginChainCustomizer} bean, in order, before its catch-all rule. All of it hangs from
 * {@link SocialProvidersCondition}: with no provider configured there is no bean here at all, so the application
 * behaves exactly as it does without the feature.
 */
@Configuration(value = "socialWebConfiguration", proxyBeanMethods = false)
@Conditional(SocialProvidersCondition.class)
@EnableConfigurationProperties(SocialProperties.class)
public class SocialConfiguration {

    // tag::social-registrations[]
    /**
     * Declares the registrations of the configured providers; the repository cannot be empty, which is why this
     * configuration exists only when one provider is configured at least.
     *
     * @param properties settings of the providers.
     * @param mapper     maps the settings onto registrations.
     * @return the repository.
     */
    @Bean
    public ClientRegistrationRepository socialClientRegistrationRepository(
            final SocialProperties properties, final ClientRegistrationMapper mapper) {
        return new InMemoryClientRegistrationRepository(mapper.toRegistrations(properties));
    }

    /**
     * Declares the factory of the ID token decoders, with the validators of {@link IdTokenValidatorFactory} (the issuer
     * of a multi-tenant Microsoft Entra ID token is checked against the token's tenant).
     *
     * @param properties settings of the providers.
     * @return the factory.
     */
    @Bean
    public JwtDecoderFactory<ClientRegistration> socialIdTokenDecoderFactory(final SocialProperties properties) {
        final var factory = new OidcIdTokenDecoderFactory();
        factory.setJwtValidatorFactory(new IdTokenValidatorFactory(properties));
        return factory;
    }
    // end::social-registrations[]

    /**
     * Declares the resolver of the local account of a sign-in, with the account status rules of the other sign-in
     * methods.
     *
     * @param useCase            use case that finds, links or provisions the account.
     * @param userDetailsService loads the accounts.
     * @return the resolver.
     */
    @Bean
    public FederatedAccountResolver federatedAccountResolver(
            final ResolveFederatedLoginUseCase useCase, final UserDetailsService userDetailsService) {
        return new FederatedAccountResolver(useCase, new AccountStatusUserDetailsService(userDetailsService));
    }

    /**
     * Declares the client that reads the verified e-mail address of a GitHub user.
     *
     * @return the client.
     */
    @Bean
    public GitHubEmailClient gitHubEmailClient() {
        return new GitHubEmailClient(RestClient.create());
    }

    /**
     * Declares the user service of the OpenID Connect providers.
     *
     * @param resolver resolves the account.
     * @param mapper   builds the local principal.
     * @return the service.
     */
    @Bean
    public FederatedOidcUserService federatedOidcUserService(
            final FederatedAccountResolver resolver, final FederatedUserMapper mapper) {
        return new FederatedOidcUserService(new OidcUserService(), resolver, mapper);
    }

    /**
     * Declares the user service of the OAuth 2.0 providers (GitHub).
     *
     * @param emailClient reads the verified e-mail address.
     * @param resolver    resolves the account.
     * @param mapper      builds the local principal.
     * @return the service.
     */
    @Bean
    public FederatedOAuth2UserService federatedOAuth2UserService(final GitHubEmailClient emailClient,
            final FederatedAccountResolver resolver, final FederatedUserMapper mapper) {
        return new FederatedOAuth2UserService(new DefaultOAuth2UserService(), emailClient, resolver, mapper);
    }

    /**
     * Declares the selector of the factor a sign-in proved.
     *
     * @param properties settings of the providers.
     * @param mapper     reads the upstream {@code amr}.
     * @return the selector.
     */
    @Bean
    public FederatedFactorSelector federatedFactorSelector(
            final SocialProperties properties, final FederatedUserMapper mapper) {
        return new FederatedFactorSelector(properties, mapper);
    }

    /**
     * Declares the link of each configured provider on the login page.
     *
     * @param properties settings of the providers.
     * @return the fragment.
     */
    @Bean
    public SocialLoginMethodFragment socialLoginMethodFragment(final SocialProperties properties) {
        return new SocialLoginMethodFragment(
                properties.enabledProviders().keySet().stream().map(IdentityProvider::id).toList());
    }

    // tag::social-chain-customizer[]
    /**
     * Declares the customizer that enables {@code http.oauth2Login(...)}. It is applied after the phone page one.
     *
     * @param repository     registrations of the configured providers.
     * @param oidcService    user service of the OpenID Connect providers.
     * @param oauth2Service  user service of the OAuth 2.0 providers.
     * @param grantor        adds the factor authority.
     * @param selector       chooses the factor.
     * @param apple          generates the Apple client secret; absent while Apple is not configured.
     * @param properties     settings of the providers, for the Apple client id.
     * @return the customizer.
     */
    @Bean
    @Order(SocialChainCustomizer.ORDER)
    public LoginChainCustomizer socialChainCustomizer(final ClientRegistrationRepository repository,
            final FederatedOidcUserService oidcService, final FederatedOAuth2UserService oauth2Service,
            final FactorGrantor grantor, final FederatedFactorSelector selector,
            final ObjectProvider<AppleClientSecretGenerator> apple, final SocialProperties properties) {
        final var securityContextRepository = new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
        final var successHandler = new FederatedAuthenticationSuccessHandler(
                grantor, selector, securityContextRepository, new SavedRequestAwareAuthenticationSuccessHandler());
        final var tokenClient = new RestClientAuthorizationCodeTokenResponseClient();
        final var resolver = new DefaultOAuth2AuthorizationRequestResolver(repository, "/oauth2/authorization");
        final var generator = apple.getIfAvailable();
        if (generator != null) {
            final var clientId = properties.find(IdentityProvider.APPLE).orElseThrow().clientId();
            tokenClient.setParametersCustomizer(new AppleTokenRequestCustomizer(clientId, generator));
            resolver.setAuthorizationRequestCustomizer(new AppleAuthorizationRequestCustomizer(clientId));
        }
        return new SocialChainCustomizer(repository, oidcService, oauth2Service, successHandler,
                securityContextRepository, tokenClient, resolver, generator != null);
    }
    // end::social-chain-customizer[]

    /**
     * Declares the generator of the Apple client secret, only while Apple is configured.
     */
    @Configuration(value = "socialAppleConfiguration", proxyBeanMethods = false)
    @Conditional(AppleProviderCondition.class)
    static class AppleConfiguration {

        /**
         * Declares the generator, whose key is read (and refused at startup when it is not an ES256 key) once.
         *
         * @param properties settings of the providers.
         * @param parser     reads the private key.
         * @param clock      source of the current time.
         * @return the generator.
         */
        @Bean
        public AppleClientSecretGenerator appleClientSecretGenerator(
                final SocialProperties properties, final ApplePrivateKeyParser parser, final Clock clock) {
            final var apple = properties.find(IdentityProvider.APPLE).orElseThrow();
            return new AppleClientSecretGenerator(apple, parser.parse(apple.privateKey()), clock);
        }
    }
}
