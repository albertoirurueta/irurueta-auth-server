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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.passkeys.AccountStatusUserDetailsService;
import com.irurueta.authserver.authorization.application.ott.RequestMagicLinkUseCase;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.ott.VerifyOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * Wires the one-time token methods into the login/UI chain. The filters are built here and handed to the customizer,
 * never declared as beans: Spring Boot would register every {@code Filter} bean in the servlet container, outside the
 * security chain. The providers are held in {@link OttProviders}, not declared as {@code AuthenticationProvider}
 * beans, for the reason given there. The bean is named apart from the application layer's configuration of the same
 * name.
 */
@Configuration(value = "ottWebConfiguration", proxyBeanMethods = false)
public class OttConfiguration {

    /**
     * Declares the rules about the session a second factor is presented in.
     *
     * @param factorRegistry tells the strength of each factor authority.
     * @return the rules.
     */
    @Bean
    public PrimaryFactorSession primaryFactorSession(final AuthenticationFactorRegistry factorRegistry) {
        return new PrimaryFactorSession(factorRegistry);
    }

    // tag::ott-resolver-bean[]
    /**
     * Declares the resolver of the token request of {@code POST /ott/generate}.
     *
     * @param ottPolicy the rules of one-time tokens, which set the lifetime of each kind.
     * @return the resolver.
     */
    @Bean
    public OttGenerateRequestResolver ottGenerateRequestResolver(final OttPolicy ottPolicy) {
        return new OttGenerateRequestResolver(ottPolicy);
    }
    // end::ott-resolver-bean[]

    /**
     * Declares the handler that delivers a generated token.
     *
     * @param requestOneTimeCodeUseCase starts a numeric code.
     * @param requestMagicLinkUseCase   requests the delivery of a magic link.
     * @param tokenService              store of the magic link tokens.
     * @param linkFactory               builds the magic link.
     * @param secondFactorChannels      decides which channels may be the second factor of the signed-in user.
     * @return the handler.
     */
    @Bean
    public OttGenerationSuccessHandler ottGenerationSuccessHandler(
            final RequestOneTimeCodeUseCase requestOneTimeCodeUseCase,
            final RequestMagicLinkUseCase requestMagicLinkUseCase, final OneTimeTokenService tokenService,
            final OttLinkFactory linkFactory, final OttSecondFactorChannels secondFactorChannels) {
        return new OttGenerationSuccessHandler(requestOneTimeCodeUseCase, requestMagicLinkUseCase, tokenService,
                linkFactory, secondFactorChannels);
    }

    /**
     * Declares the authentication providers of the one-time token methods. The accounts are loaded through the user
     * service wrapped so a disabled, locked or expired one is refused.
     *
     * @param tokenService             store of the magic link tokens.
     * @param userDetailsService       loads the accounts.
     * @param verifyOneTimeCodeUseCase verifies a numeric code.
     * @param factorGrantor            adds the factor authority to an authentication.
     * @param primaryFactorSession     rules about the session a second factor is presented in.
     * @param secondFactorChannels     decides which channels may be the second factor of the signed-in user.
     * @return the providers.
     */
    @Bean
    public OttProviders ottProviders(final OneTimeTokenService tokenService,
            final UserDetailsService userDetailsService, final VerifyOneTimeCodeUseCase verifyOneTimeCodeUseCase,
            final FactorGrantor factorGrantor, final PrimaryFactorSession primaryFactorSession,
            final OttSecondFactorChannels secondFactorChannels) {
        final var users = new AccountStatusUserDetailsService(userDetailsService);
        return new OttProviders(
                new OttLinkAuthenticationProvider(tokenService, users, factorGrantor, primaryFactorSession,
                        secondFactorChannels),
                new OttCodeAuthenticationProvider(verifyOneTimeCodeUseCase, users, factorGrantor),
                new OttSecondFactorAuthenticationProvider(verifyOneTimeCodeUseCase, factorGrantor,
                        secondFactorChannels));
    }

    // tag::ott-chain-customizer[]
    /**
     * Installs the one-time token methods in the login/UI chain.
     *
     * @param rateLimiter          limits the token requests and submissions.
     * @param requestResolver      resolves the token Spring's filter generates.
     * @param successHandler       delivers the generated token.
     * @param tokenService         store of the magic link tokens.
     * @param providers            the authentication providers.
     * @param primaryFactorSession rules about the session a second factor is presented in.
     * @return the customizer.
     */
    @Bean
    @Order(OttChainCustomizer.ORDER)
    public LoginChainCustomizer ottChainCustomizer(final OttRateLimiter rateLimiter,
            final OttGenerateRequestResolver requestResolver, final OttGenerationSuccessHandler successHandler,
            final OneTimeTokenService tokenService, final OttProviders providers,
            final PrimaryFactorSession primaryFactorSession) {
        return new OttChainCustomizer(new OttRateLimitFilter(rateLimiter), requestResolver, successHandler,
                tokenService, new OttAuthenticationConverter(), providers.link(), providers.code(),
                new OttAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler()),
                new OttAuthenticationFailureHandler(),
                new OttSecondFactorFilter(new ProviderManager(providers.secondFactor()), primaryFactorSession));
    }
    // end::ott-chain-customizer[]

    /**
     * Keeps the phone page and its form posts behind the multi-factor policy.
     *
     * @param authorizationManager applies the multi-factor policy.
     * @return the customizer.
     */
    @Bean
    @Order(PhonePageChainCustomizer.ORDER)
    public LoginChainCustomizer phonePageChainCustomizer(final MfaAuthorizationManager authorizationManager) {
        return new PhonePageChainCustomizer(authorizationManager);
    }
}
