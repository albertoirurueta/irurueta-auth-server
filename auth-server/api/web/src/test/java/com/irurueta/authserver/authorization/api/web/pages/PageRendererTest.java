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

package com.irurueta.authserver.authorization.api.web.pages;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.login.BrandingProperties;
import com.irurueta.authserver.authorization.api.web.login.BrandingProvider;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;

/**
 * Unit tests of {@link PageRenderer}.
 */
@ExtendWith(MockitoExtension.class)
class PageRendererTest {

    /** Name of the view the tests render. */
    private static final String VIEW_NAME = "page";

    /** Markup the view writes, with a character outside ISO-8859-1. */
    private static final String HTML = "<p>Señal ✓</p>";

    /** Branding of the tests. */
    private static final BrandingProperties BRANDING = new BrandingProperties("Acme", null, null);

    /** First view resolver, which does not know the view. */
    @Mock
    private ViewResolver first;

    /** Second view resolver, which knows the view. */
    @Mock
    private ViewResolver second;

    /** The view of the page. */
    @Mock
    private View view;

    /** Supplies the branding. */
    @Mock
    private BrandingProvider brandingProvider;

    /** The current request. */
    private MockHttpServletRequest request;

    /** The current response. */
    private MockHttpServletResponse response;

    /**
     * Creates the request and the response of each test.
     */
    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        request.addPreferredLocale(Locale.FRENCH);
        response = new MockHttpServletResponse();
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    }

    /**
     * Verifies that the view of the first resolver that knows it is rendered with the model and the branding, in the
     * locale of the request, and that its markup is answered as {@code text/html} instead of being written to the
     * response.
     *
     * @throws Exception if the view mock cannot be stubbed.
     */
    @Test
    void render_whenSecondResolverKnowsTheView_answersItsMarkupWithTheBranding() throws Exception {
        when(brandingProvider.branding()).thenReturn(BRANDING);
        when(second.resolveViewName(VIEW_NAME, Locale.FRENCH)).thenReturn(view);
        doAnswer(invocation -> {
            invocation.<HttpServletResponse>getArgument(2).getWriter().write(HTML);
            return null;
        }).when(view).render(anyMap(), eq(request), any(HttpServletResponse.class));

        final var answer = renderer(List.of(first, second)).render(VIEW_NAME, Map.of("key", "value"));

        assertEquals(HttpStatus.OK, answer.getStatusCode());
        assertEquals(PageRenderer.TEXT_HTML_UTF8, answer.getHeaders().getContentType());
        assertTrue(MediaType.TEXT_HTML.isCompatibleWith(answer.getHeaders().getContentType()));
        assertEquals(HTML, answer.getBody());
        assertEquals("", response.getContentAsString());
        final var captor = ArgumentCaptor.<Map<String, ?>>captor();
        verify(view).render(captor.capture(), eq(request), any(HttpServletResponse.class));
        assertEquals("value", captor.getValue().get("key"));
        assertSame(BRANDING, captor.getValue().get(BrandingProvider.MODEL_ATTRIBUTE));
    }

    /**
     * Verifies that a view no resolver knows is an error.
     *
     * @throws Exception if the resolver mock cannot be stubbed.
     */
    @Test
    void render_whenNoResolverKnowsTheView_throwsIllegalStateException() throws Exception {
        final var renderer = renderer(List.of(first));
        final var model = Map.<String, Object>of();

        final var error = assertThrows(IllegalStateException.class, () -> renderer.render(VIEW_NAME, model));

        assertTrue(error.getMessage().contains(VIEW_NAME));
        verify(first).resolveViewName(VIEW_NAME, Locale.FRENCH);
    }

    /**
     * Verifies that a failing resolver is reported.
     *
     * @throws Exception if the resolver mock cannot be stubbed.
     */
    @Test
    void render_whenResolverFails_throwsIllegalStateException() throws Exception {
        final var failure = new IllegalArgumentException("broken");
        when(first.resolveViewName(VIEW_NAME, Locale.FRENCH)).thenThrow(failure);
        final var renderer = renderer(List.of(first));
        final var model = Map.<String, Object>of();

        final var error = assertThrows(IllegalStateException.class, () -> renderer.render(VIEW_NAME, model));

        assertSame(failure, error.getCause());
    }

    /**
     * Verifies that a view that cannot be rendered is reported.
     *
     * @throws Exception if the view mock cannot be stubbed.
     */
    @Test
    void render_whenViewFails_throwsIllegalStateException() throws Exception {
        final var failure = new IllegalArgumentException("template error");
        when(first.resolveViewName(VIEW_NAME, Locale.FRENCH)).thenReturn(view);
        doThrow(failure).when(view).render(anyMap(), eq(request), any(HttpServletResponse.class));
        final var renderer = renderer(List.of(first));
        final var model = Map.<String, Object>of();

        final var error = assertThrows(IllegalStateException.class, () -> renderer.render(VIEW_NAME, model));

        assertSame(failure, error.getCause());
    }

    /**
     * Creates the renderer under test.
     *
     * @param resolvers the view resolvers, in their order.
     * @return the renderer.
     */
    private PageRenderer renderer(final List<ViewResolver> resolvers) {
        return new PageRenderer(resolvers, brandingProvider, request, response);
    }
}
