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

import jakarta.servlet.RequestDispatcher;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ExtendedModelMap;

/**
 * Unit tests of {@link ErrorPageController}.
 */
class ErrorPageControllerTest {

    /** A status that is not an HTTP status. */
    private static final int UNKNOWN_STATUS = 599;

    /** Controller under test. */
    private final ErrorPageController controller = new ErrorPageController();

    /**
     * Verifies that a missing page shows its own text and keeps its status.
     */
    @Test
    void page_whenStatusIsNotFound_showsTheNotFoundText() {
        final var response = new MockHttpServletResponse();
        final var model = new ExtendedModelMap();

        final var view = controller.page(requestWithStatus(HttpStatus.NOT_FOUND.value()), response, model);

        assertEquals("error", view);
        assertEquals(HttpStatus.NOT_FOUND.value(), response.getStatus());
        assertEquals(ErrorPageController.NOT_FOUND_KEY, model.get(ErrorPageController.MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a forbidden request shows its own text.
     */
    @Test
    void page_whenStatusIsForbidden_showsTheForbiddenText() {
        final var model = new ExtendedModelMap();

        controller.page(requestWithStatus(HttpStatus.FORBIDDEN.value()), new MockHttpServletResponse(), model);

        assertEquals(ErrorPageController.FORBIDDEN_KEY, model.get(ErrorPageController.MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that any other status shows the generic text, never the details of the failure.
     */
    @Test
    void page_whenStatusIsAnythingElse_showsTheGenericText() {
        final var request = requestWithStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        request.setAttribute(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("secret detail"));
        final var model = new ExtendedModelMap();

        controller.page(request, new MockHttpServletResponse(), model);

        assertEquals(ErrorPageController.GENERIC_KEY, model.get(ErrorPageController.MESSAGE_ATTRIBUTE));
        assertFalse(model.containsAttribute("exception"));
    }

    /**
     * Verifies that a request without a status is an internal server error.
     */
    @Test
    void page_whenStatusIsMissing_isAnInternalServerError() {
        final var response = new MockHttpServletResponse();

        controller.page(new MockHttpServletRequest(), response, new ExtendedModelMap());

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
    }

    /**
     * Verifies that an unknown status is an internal server error.
     */
    @Test
    void page_whenStatusIsUnknown_isAnInternalServerError() {
        final var response = new MockHttpServletResponse();

        controller.page(requestWithStatus(UNKNOWN_STATUS), response, new ExtendedModelMap());

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR.value(), response.getStatus());
    }

    /**
     * Verifies that the JSON answer holds the status and nothing else.
     */
    @Test
    void body_whenStatusIsGiven_holdsOnlyStatusAndReason() {
        final var answer = controller.body(requestWithStatus(HttpStatus.NOT_FOUND.value()));

        assertEquals(HttpStatus.NOT_FOUND, answer.getStatusCode());
        assertEquals(Map.of("status", HttpStatus.NOT_FOUND.value(), "error", "Not Found"), answer.getBody());
    }

    /**
     * Builds a forwarded error request.
     *
     * @param status status of the failed request.
     * @return the request.
     */
    private static MockHttpServletRequest requestWithStatus(final int status) {
        final var request = new MockHttpServletRequest();
        request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, status);
        return request;
    }
}
