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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.passkeys.PasskeyProperties;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Unit tests of {@link PasskeyConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyConfigurationTest {

    /** Manager that applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Loads the accounts. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Resolves the account of the signed-in user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Tells whether the second factor of a user is locked. */
    @Mock
    private CheckSecondFactorLockoutUseCase lockoutUseCase;

    /**
     * Verifies that the customizer bean is the chain customizer of the passkeys, ordered after the TOTP one.
     *
     * @throws NoSuchMethodException if the bean method does not exist.
     */
    @Test
    void passkeyChainCustomizer_whenCalled_returnsTheChainCustomizerOrderedAfterTotp()
            throws NoSuchMethodException {
        final var properties = new PasskeyProperties("Name", "localhost", List.of("http://localhost:9000"));

        final var customizer = new PasskeyConfiguration().passkeyChainCustomizer(properties, authorizationManager,
                userDetailsService, userResolver, lockoutUseCase);

        assertInstanceOf(PasskeyChainCustomizer.class, customizer);
        final var order = PasskeyConfiguration.class.getMethod("passkeyChainCustomizer", PasskeyProperties.class,
                MfaAuthorizationManager.class, UserDetailsService.class, SecondFactorUserResolver.class,
                CheckSecondFactorLockoutUseCase.class).getAnnotation(Order.class);
        assertEquals(PasskeyChainCustomizer.ORDER, order.value());
    }
}
