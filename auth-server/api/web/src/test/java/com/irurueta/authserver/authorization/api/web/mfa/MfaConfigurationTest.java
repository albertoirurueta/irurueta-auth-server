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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.application.mfa.IsUserMfaRequiredUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Unit tests of {@link MfaConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class MfaConfigurationTest {

    /** Tells whether a user requires MFA. */
    @Mock
    private IsUserMfaRequiredUseCase isUserMfaRequiredUseCase;

    /** Resolves the client of a request. */
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    /** Configuration under test. */
    private final MfaConfiguration configuration = new MfaConfiguration();

    /**
     * Verifies that the registry holds the factors it is given.
     */
    @Test
    void authenticationFactorRegistry_whenFactorsAreGiven_registersThem() {
        final var factor = new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY);

        assertEquals(List.of(factor), configuration.authenticationFactorRegistry(List.of(factor)).all());
    }

    /**
     * Verifies that every collaborator bean is built.
     */
    @Test
    void beans_whenBuilt_areNotNull() {
        final var registry = configuration.authenticationFactorRegistry(List.of());
        final var entryPoint = configuration.secondFactorRequiredEntryPoint();
        final var manager = configuration.mfaAuthorizationManager(new MfaPolicy(), registry,
                isUserMfaRequiredUseCase, registeredClientRepository);

        assertNotNull(entryPoint);
        assertNotNull(manager);
        assertNotNull(configuration.mfaLoginChainCustomizer(manager, registry, entryPoint));
        final var reauthenticationEntryPoint = configuration.reauthenticationEntryPoint();
        assertNotNull(reauthenticationEntryPoint);
        assertNotNull(configuration.mfaProtocolChainCustomizer(manager, entryPoint, reauthenticationEntryPoint));
        assertNotNull(configuration.stepUpProtocolChainCustomizer(new FactorTimeline(registry, new MfaPolicy()),
                Clock.systemUTC()));
    }
}
