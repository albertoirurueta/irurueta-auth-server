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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import com.irurueta.authserver.authorization.api.web.mfa.AuthenticationFactorRegistry;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.ott.ResolveOttDestinationUseCase;
import com.irurueta.authserver.authorization.application.ott.VerifyOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.userdetails.UserDetailsService;

/** Unit tests of {@link OttConfiguration}. */
class OttConfigurationTest {

    /** Length of a code. */
    private static final int CODE_LENGTH = 6;

    /** Attempts tolerated. */
    private static final int MAX_ATTEMPTS = 5;

    /** Configuration under test. */
    private final OttConfiguration configuration = new OttConfiguration();

    /** Collaborators, all mocks. */
    private final OneTimeTokenService tokenService = mock(OneTimeTokenService.class);

    /** The rules of one-time tokens. */
    private final OttPolicy policy = new OttPolicy(CODE_LENGTH, Duration.ofMinutes(1), Duration.ofMinutes(2),
            MAX_ATTEMPTS);

    /** The rules about the session. */
    private final PrimaryFactorSession primaryFactorSession =
            configuration.primaryFactorSession(new AuthenticationFactorRegistry(List.of()));

    /** The primary factor session is built over the registry. */
    @Test
    void primaryFactorSession_whenCalled_returnsTheRules() {
        assertNotNull(primaryFactorSession);
    }

    /** The resolver is built over the policy. */
    @Test
    void ottGenerateRequestResolver_whenCalled_returnsTheResolver() {
        assertNotNull(configuration.ottGenerateRequestResolver(policy));
    }

    /** The handler is built over its collaborators. */
    @Test
    void ottGenerationSuccessHandler_whenCalled_returnsTheHandler() {
        assertNotNull(configuration.ottGenerationSuccessHandler(mock(RequestOneTimeCodeUseCase.class),
                mock(ResolveOttDestinationUseCase.class), mock(OttDelivery.class), tokenService, policy,
                mock(OttLinkFactory.class)));
    }

    /** The three providers are built and kept together. */
    @Test
    void ottProviders_whenCalled_returnsTheThreeProviders() {
        final var providers = configuration.ottProviders(tokenService, mock(UserDetailsService.class),
                mock(VerifyOneTimeCodeUseCase.class), mock(FactorGrantor.class), primaryFactorSession);

        assertInstanceOf(OttLinkAuthenticationProvider.class, providers.link());
        assertInstanceOf(OttCodeAuthenticationProvider.class, providers.code());
        assertInstanceOf(OttSecondFactorAuthenticationProvider.class, providers.secondFactor());
    }

    /** The customizer is built, and ordered after the TOTP and passkey ones. */
    @Test
    void ottChainCustomizer_whenCalled_returnsTheCustomizerOrderedAfterThePasskeyOne() throws Exception {
        final var providers = configuration.ottProviders(tokenService, mock(UserDetailsService.class),
                mock(VerifyOneTimeCodeUseCase.class), mock(FactorGrantor.class), primaryFactorSession);

        final var customizer = configuration.ottChainCustomizer(mock(OttRateLimiter.class),
                configuration.ottGenerateRequestResolver(policy), mock(OttGenerationSuccessHandler.class),
                tokenService, providers, primaryFactorSession);

        assertInstanceOf(OttChainCustomizer.class, customizer);
        final var order = AnnotationUtils.findAnnotation(OttConfiguration.class.getMethod("ottChainCustomizer",
                OttRateLimiter.class, OttGenerateRequestResolver.class, OttGenerationSuccessHandler.class,
                OneTimeTokenService.class, OttProviders.class, PrimaryFactorSession.class), Order.class);
        assertEquals(OttChainCustomizer.ORDER, order.value());
    }

    /** The phone page customizer is built, and ordered after the one-time token one. */
    @Test
    void phonePageChainCustomizer_whenCalled_returnsTheCustomizerOrderedAfterTheOttOne() throws Exception {
        final var customizer = configuration.phonePageChainCustomizer(mock(MfaAuthorizationManager.class));

        assertInstanceOf(PhonePageChainCustomizer.class, customizer);
        final var order = AnnotationUtils.findAnnotation(OttConfiguration.class.getMethod("phonePageChainCustomizer",
                MfaAuthorizationManager.class), Order.class);
        assertEquals(PhonePageChainCustomizer.ORDER, order.value());
    }
}
