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

package com.irurueta.authserver.authorization.api.web.error;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.login.BrandingProperties;
import com.irurueta.authserver.authorization.api.web.login.BrandingProvider;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Unit tests of {@link ErrorPageViewResolver}.
 */
@ExtendWith(MockitoExtension.class)
class ErrorPageViewResolverTest {

    /** Branding of the tests. */
    private static final BrandingProperties BRANDING = new BrandingProperties("Acme", null, null);

    /** Supplies the branding. */
    @Mock
    private BrandingProvider brandingProvider;

    /** Resolver under test. */
    @InjectMocks
    private ErrorPageViewResolver resolver;

    /**
     * Provides each status with the message key it shows.
     *
     * @return the status and the expected message key.
     */
    private static Stream<Arguments> statuses() {
        return Stream.of(
                Arguments.of(HttpStatus.NOT_FOUND, ErrorPageViewResolver.NOT_FOUND_KEY),
                Arguments.of(HttpStatus.FORBIDDEN, ErrorPageViewResolver.FORBIDDEN_KEY),
                Arguments.of(HttpStatus.BAD_REQUEST, ErrorPageViewResolver.GENERIC_KEY),
                Arguments.of(HttpStatus.INTERNAL_SERVER_ERROR, ErrorPageViewResolver.GENERIC_KEY));
    }

    /**
     * Verifies that the error template is chosen with the message key of the status and the branding, keeps the
     * status, and passes on nothing of the model the error controller offers.
     *
     * @param status     the status of the failed request.
     * @param messageKey the message key the page must show.
     */
    @ParameterizedTest
    @MethodSource("statuses")
    void resolveErrorView_whenStatusIsGiven_choosesItsMessageAndKeepsTheDetailsOut(final HttpStatus status,
            final String messageKey) {
        when(brandingProvider.branding()).thenReturn(BRANDING);

        final var view = resolver.resolveErrorView(new MockHttpServletRequest(), status,
                Map.of("message", "secret detail", "path", "/internal", "trace", "stack"));

        assertEquals(ErrorPageViewResolver.VIEW_NAME, view.getViewName());
        assertEquals(status, view.getStatus());
        assertEquals(messageKey, view.getModel().get(ErrorPageViewResolver.MESSAGE_ATTRIBUTE));
        assertSame(BRANDING, view.getModel().get(BrandingProvider.MODEL_ATTRIBUTE));
        assertFalse(view.getModel().containsKey("message"));
        assertFalse(view.getModel().containsKey("path"));
        assertFalse(view.getModel().containsKey("trace"));
    }
}
