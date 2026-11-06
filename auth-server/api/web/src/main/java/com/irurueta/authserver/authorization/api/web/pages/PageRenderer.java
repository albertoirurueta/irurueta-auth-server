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

import com.irurueta.authserver.authorization.api.web.login.BrandingProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.springframework.web.util.ContentCachingResponseWrapper;

/**
 * Renders a server-rendered page (a Thymeleaf template) to the {@code text/html} answer of an operation generated from
 * the pages contract. The view is resolved through the application's view resolvers, in their order, with the locale
 * of the request, and rendered against the current request into a wrapper that captures what it writes, so everything
 * a template relies on keeps working: the CSRF hidden field that {@code th:action} adds, {@code @{...}} links and the
 * messages. Every page gets the branding as the {@value BrandingProvider#MODEL_ATTRIBUTE} model attribute.
 */
@Component
@RequiredArgsConstructor
public class PageRenderer {

    /** Media type of the rendered pages. */
    static final MediaType TEXT_HTML_UTF8 = new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8);

    /** View resolvers of the application, in their order. */
    private final List<ViewResolver> viewResolvers;

    /** Supplies the branding of the pages. */
    private final BrandingProvider brandingProvider;

    /** The current request, injected as a thread-bound proxy. */
    private final HttpServletRequest request;

    /** The current response, injected as a thread-bound proxy. */
    private final HttpServletResponse response;

    // tag::page-renderer[]
    /**
     * Renders a page.
     *
     * @param viewName name of the view (the Thymeleaf template).
     * @param model    model attributes of the page; the branding is added to them.
     * @return a {@code 200} with the page as {@code text/html}.
     * @throws IllegalStateException if no view resolver knows the view, or the view cannot be rendered.
     */
    public ResponseEntity<String> render(final String viewName, final Map<String, ?> model) {
        final var locale = RequestContextUtils.getLocale(request);
        final var view = resolve(viewName, locale);
        final var attributes = new LinkedHashMap<String, Object>(model);
        attributes.put(BrandingProvider.MODEL_ATTRIBUTE, brandingProvider.branding());
        final var capture = new ContentCachingResponseWrapper(response);
        try {
            view.render(attributes, request, capture);
        } catch (final Exception e) {
            throw new IllegalStateException("The page " + viewName + " cannot be rendered", e);
        }
        final var html = new String(capture.getContentAsByteArray(), Charset.forName(capture.getCharacterEncoding()));
        return ResponseEntity.ok().contentType(TEXT_HTML_UTF8).body(html);
    }
    // end::page-renderer[]

    /**
     * Resolves a view through the view resolvers, in their order.
     *
     * @param viewName name of the view.
     * @param locale   locale of the request.
     * @return the view of the first resolver that knows it.
     * @throws IllegalStateException if no view resolver knows the view.
     */
    private View resolve(final String viewName, final Locale locale) {
        return viewResolvers.stream()
                .map(resolver -> resolveWith(resolver, viewName, locale))
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No view named " + viewName));
    }

    /**
     * Resolves a view with one resolver.
     *
     * @param resolver the view resolver.
     * @param viewName name of the view.
     * @param locale   locale of the request.
     * @return the view, or {@code null} when the resolver does not know it.
     * @throws IllegalStateException if the resolver fails.
     */
    private static View resolveWith(final ViewResolver resolver, final String viewName, final Locale locale) {
        try {
            return resolver.resolveViewName(viewName, locale);
        } catch (final Exception e) {
            throw new IllegalStateException("The view " + viewName + " cannot be resolved", e);
        }
    }
}
