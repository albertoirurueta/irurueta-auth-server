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

import com.irurueta.authserver.authorization.api.web.login.BrandingProvider;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.webmvc.autoconfigure.error.ErrorViewResolver;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

/**
 * Chooses the error page Spring Boot's {@code BasicErrorController} renders for a browser: the {@code error} template
 * with a generic text picked from the status only, and the branding. The model the controller offers (timestamp, path,
 * exception, ...) is deliberately not passed on, so the page never shows a stack trace, an exception message, the
 * requested path or anything else that could leak internals. Clients that do not accept HTML get the controller's
 * JSON body, which {@code spring.web.error.include-*} keeps to the timestamp, the status and its reason phrase.
 */
@Component
@RequiredArgsConstructor
public class ErrorPageViewResolver implements ErrorViewResolver {

    /** Name of the error template. */
    static final String VIEW_NAME = "error";

    /** Name of the model attribute that holds the key of the message to show. */
    static final String MESSAGE_ATTRIBUTE = "messageKey";

    /** Message key shown for a missing page. */
    static final String NOT_FOUND_KEY = "error.notFound";

    /** Message key shown for a forbidden request. */
    static final String FORBIDDEN_KEY = "error.forbidden";

    /** Message key shown for any other error. */
    static final String GENERIC_KEY = "error.message";

    /** Supplies the branding of the pages. */
    private final BrandingProvider brandingProvider;

    /**
     * Resolves the error page of a status.
     *
     * @param request the forwarded request.
     * @param status  status of the failed request.
     * @param model   model offered by the error controller; not used, so none of its details reach the page.
     * @return the error view, with the message key and the branding, answered with the status.
     */
    @Override
    public ModelAndView resolveErrorView(final HttpServletRequest request, final HttpStatus status,
            final Map<String, Object> model) {
        final var messageKey = switch (status) {
            case NOT_FOUND -> NOT_FOUND_KEY;
            case FORBIDDEN -> FORBIDDEN_KEY;
            default -> GENERIC_KEY;
        };
        return new ModelAndView(VIEW_NAME,
                Map.of(MESSAGE_ATTRIBUTE, messageKey, BrandingProvider.MODEL_ATTRIBUTE, brandingProvider.branding()),
                status);
    }
}
