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

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Renders the errors of the server-rendered pages. The page shows a generic text chosen from the status only: never
 * a stack trace, an exception message, the requested path or anything else that could leak internals. Clients that
 * do not accept HTML get the same minimal information as JSON. It replaces Spring Boot's default error controller.
 */
// HTML page, not part of the OpenAPI contract
@Hidden
@Controller
public class ErrorPageController implements ErrorController {

    /** Path of the error page. */
    public static final String ERROR_PATH = "/error";

    /** Name of the model attribute that holds the key of the message to show. */
    static final String MESSAGE_ATTRIBUTE = "messageKey";

    /** Message key shown for a missing page. */
    static final String NOT_FOUND_KEY = "error.notFound";

    /** Message key shown for a forbidden request. */
    static final String FORBIDDEN_KEY = "error.forbidden";

    /** Message key shown for any other error. */
    static final String GENERIC_KEY = "error.message";

    /**
     * Renders the error page, with the status of the failed request.
     *
     * @param request  the forwarded request.
     * @param response the response, which receives the status of the failed request.
     * @param model    model of the view.
     * @return the error template name.
     */
    @RequestMapping(value = ERROR_PATH, produces = MediaType.TEXT_HTML_VALUE)
    public String page(final HttpServletRequest request, final HttpServletResponse response, final Model model) {
        final var status = statusOf(request);
        response.setStatus(status.value());
        model.addAttribute(MESSAGE_ATTRIBUTE, switch (status) {
            case NOT_FOUND -> NOT_FOUND_KEY;
            case FORBIDDEN -> FORBIDDEN_KEY;
            default -> GENERIC_KEY;
        });
        return "error";
    }

    /**
     * Answers the clients that do not accept HTML with the status only.
     *
     * @param request the forwarded request.
     * @return the status and its reason phrase.
     */
    @RequestMapping(ERROR_PATH)
    public ResponseEntity<Map<String, Object>> body(final HttpServletRequest request) {
        final var status = statusOf(request);
        return ResponseEntity.status(status).body(Map.of("status", status.value(), "error", status.getReasonPhrase()));
    }

    /**
     * Gets the status of the failed request.
     *
     * @param request the forwarded request.
     * @return its status; internal server error when it is missing or unknown.
     */
    private static HttpStatus statusOf(final HttpServletRequest request) {
        final var code = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        final var status = code instanceof Integer value ? HttpStatus.resolve(value) : null;
        return status == null ? HttpStatus.INTERNAL_SERVER_ERROR : status;
    }
}
