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
package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Unit tests of {@link BrandingProvider}.
 */
@ExtendWith(MockitoExtension.class)
class BrandingProviderTest {

    /** Provider of the branding. */
    @Mock
    private ObjectProvider<BrandingProperties> provider;

    /** Provider under test. */
    @InjectMocks
    private BrandingProvider brandingProvider;

    /**
     * Verifies that the configured branding is exposed.
     */
    @Test
    void branding_whenPropertiesAreEnabled_returnsConfiguredBranding() {
        final var configured = new BrandingProperties("Acme", null, null);
        when(provider.getIfAvailable(any())).thenReturn(configured);

        assertSame(configured, brandingProvider.branding());
    }

    /**
     * Verifies that the defaults are exposed when the properties are not enabled.
     */
    @Test
    void branding_whenPropertiesAreNotEnabled_returnsDefaults() {
        when(provider.getIfAvailable(any())).thenAnswer(invocation ->
                invocation.<Supplier<BrandingProperties>>getArgument(0).get());

        assertEquals(BrandingProperties.DEFAULT_APPLICATION_NAME, brandingProvider.branding().applicationName());
    }

    /**
     * Verifies the name of the model attribute the templates read.
     */
    @Test
    void modelAttribute_whenRead_isBranding() {
        assertEquals("branding", BrandingProvider.MODEL_ATTRIBUTE);
    }
}
