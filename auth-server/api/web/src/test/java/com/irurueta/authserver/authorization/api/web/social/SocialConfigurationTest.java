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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.application.social.LinkIdentityUseCase;
import com.irurueta.authserver.authorization.application.social.ResolveFederatedLoginUseCase;
import com.irurueta.authserver.authorization.domain.social.VerifiedEmailLookup;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Unit tests of {@link SocialConfiguration} and of its nested Apple configuration.
 */
class SocialConfigurationTest {

    /** Secret of the tests, never a real one. */
    private static final String SECRET = "not-a-secret";

    /** Number of dot-separated parts of a signed JWT. */
    private static final int JWT_PARTS = 3;

    /** Configuration under test. */
    private final SocialConfiguration configuration = new SocialConfiguration();

    /** Settings with Google and GitHub enabled. */
    private final SocialProperties properties = new SocialProperties(Map.of(
            "google", new SocialProperties.Provider("g", SECRET, false, null, null, null, null, null, null),
            "github", new SocialProperties.Provider("h", SECRET, false, null, null, null, null, null, null)));

    /**
     * Verifies that the whole configuration hangs from the condition and binds the settings.
     */
    @Test
    void annotations_whenRead_conditionTheConfigurationAndBindTheSettings() {
        assertEquals(SocialProvidersCondition.class,
                SocialConfiguration.class.getAnnotation(Conditional.class).value()[0]);
        assertEquals(SocialProperties.class,
                SocialConfiguration.class.getAnnotation(EnableConfigurationProperties.class).value()[0]);
        assertEquals(AppleProviderCondition.class,
                SocialConfiguration.AppleConfiguration.class.getAnnotation(Conditional.class).value()[0]);
    }

    /**
     * Verifies that the repository holds one registration per enabled provider.
     */
    @Test
    void socialClientRegistrationRepository_whenProvidersAreEnabled_holdsTheirRegistrations() {
        final var repository = configuration.socialClientRegistrationRepository(properties,
                new ClientRegistrationMapper());

        assertNotNull(repository.findByRegistrationId("google"));
        assertNotNull(repository.findByRegistrationId("github"));
        assertNull(repository.findByRegistrationId("apple"));
    }

    /**
     * Verifies that the decoder factory is the framework's one.
     */
    @Test
    void socialIdTokenDecoderFactory_whenCalled_returnsTheFrameworksFactory() {
        assertInstanceOf(OidcIdTokenDecoderFactory.class, configuration.socialIdTokenDecoderFactory(properties));
    }

    /**
     * Verifies that the collaborators are built: the resolver, both user services, the selector and the login
     * fragment, which lists the enabled providers in order.
     */
    @Test
    void beans_whenCalled_buildTheCollaborators() {
        final var resolver = configuration.federatedAccountResolver(mock(ResolveFederatedLoginUseCase.class),
                mock(UserDetailsService.class), mock(LinkIdentityUseCase.class), mock(PendingIdentityLinks.class));
        final var mapper = new FederatedUserMapper();
        final var emailLookup = mock(VerifiedEmailLookup.class);

        assertNotNull(resolver);
        assertNotNull(configuration.federatedOidcUserService(resolver, mapper));
        assertNotNull(configuration.federatedOAuth2UserService(emailLookup, resolver, mapper));
        assertNotNull(configuration.federatedFactorSelector(properties, mapper));
        assertEquals(List.of("google", "github"), configuration.socialLoginMethodFragment(properties).providers());
    }

    /**
     * Verifies that the chain customizer is built, ordered after the phone page one, without Apple.
     *
     * @throws NoSuchMethodException if the bean method does not exist.
     */
    @Test
    @SuppressWarnings("unchecked")
    void socialChainCustomizer_whenAppleIsAbsent_returnsTheCustomizerOrderedAfterThePhonePage()
            throws NoSuchMethodException {
        final var apple = (ObjectProvider<AppleClientSecretGenerator>) mock(ObjectProvider.class);
        when(apple.getIfAvailable()).thenReturn(null);

        final var customizer = chainCustomizer(apple);

        assertInstanceOf(SocialChainCustomizer.class, customizer);
        final var order = SocialConfiguration.class.getMethod("socialChainCustomizer",
                ClientRegistrationRepository.class,
                FederatedOidcUserService.class, FederatedOAuth2UserService.class, FactorGrantor.class,
                FederatedFactorSelector.class, ObjectProvider.class, PendingIdentityLinks.class)
                .getAnnotation(Order.class);
        assertEquals(SocialChainCustomizer.ORDER, order.value());
    }

    /**
     * Verifies that the chain customizer is built with Apple's special handling when Apple is configured.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    @SuppressWarnings("unchecked")
    void socialChainCustomizer_whenAppleIsPresent_returnsACustomizer() throws GeneralSecurityException {
        final var withApple = appleProperties();
        final var generator = new SocialConfiguration.AppleConfiguration().appleClientSecretGenerator(withApple,
                new ApplePrivateKeyParser(), Clock.systemUTC());
        final var apple = (ObjectProvider<AppleClientSecretGenerator>) mock(ObjectProvider.class);
        when(apple.getIfAvailable()).thenReturn(generator);
        final var mapper = new FederatedUserMapper();
        final var repository = configuration.socialClientRegistrationRepository(withApple,
                new ClientRegistrationMapper());
        final var resolver = configuration.federatedAccountResolver(mock(ResolveFederatedLoginUseCase.class),
                mock(UserDetailsService.class), mock(LinkIdentityUseCase.class), mock(PendingIdentityLinks.class));

        final var customizer = configuration.socialChainCustomizer(repository,
                configuration.federatedOidcUserService(resolver, mapper),
                configuration.federatedOAuth2UserService(mock(VerifiedEmailLookup.class),
                        resolver, mapper),
                new FactorGrantor(Clock.systemUTC()), configuration.federatedFactorSelector(withApple, mapper), apple,
                mock(PendingIdentityLinks.class));

        assertInstanceOf(LoginChainCustomizer.class, customizer);
        assertNotSame(generator, customizer);
    }

    /**
     * Verifies that the Apple generator reads the configured key once and signs with it, which proves the settings are
     * wired.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void appleClientSecretGenerator_whenKeyIsConfigured_signsSecretsOfTheConfiguredClient()
            throws GeneralSecurityException {
        final var generator = new SocialConfiguration.AppleConfiguration().appleClientSecretGenerator(
                appleProperties(), new ApplePrivateKeyParser(), Clock.systemUTC());

        assertEquals(JWT_PARTS, generator.generate().split("\\.").length);
    }

    /**
     * Builds the chain customizer with Google and GitHub.
     *
     * @param apple provider of the Apple generator.
     * @return the customizer.
     */
    private LoginChainCustomizer chainCustomizer(final ObjectProvider<AppleClientSecretGenerator> apple) {
        final var mapper = new FederatedUserMapper();
        final var resolver = configuration.federatedAccountResolver(mock(ResolveFederatedLoginUseCase.class),
                mock(UserDetailsService.class), mock(LinkIdentityUseCase.class), mock(PendingIdentityLinks.class));
        return configuration.socialChainCustomizer(
                configuration.socialClientRegistrationRepository(properties, new ClientRegistrationMapper()),
                configuration.federatedOidcUserService(resolver, mapper),
                configuration.federatedOAuth2UserService(mock(VerifiedEmailLookup.class),
                        resolver, mapper),
                new FactorGrantor(Clock.systemUTC()), configuration.federatedFactorSelector(properties, mapper), apple,
                mock(PendingIdentityLinks.class));
    }

    /**
     * Builds settings with Apple enabled, with a key generated here at run time.
     *
     * @return the settings.
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    private static SocialProperties appleProperties() throws GeneralSecurityException {
        final var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        final var pem = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
        return new SocialProperties(Map.of("apple", new SocialProperties.Provider("com.example.service", null, false,
                null, null, "TEAM", "KEY", pem, null)));
    }
}
