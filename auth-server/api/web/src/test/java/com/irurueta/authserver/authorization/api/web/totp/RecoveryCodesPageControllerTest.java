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
package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

/**
 * Unit tests of {@link RecoveryCodesPageController}.
 */
@ExtendWith(MockitoExtension.class)
class RecoveryCodesPageControllerTest {

    /** Recovery codes of the tests. */
    private static final List<String> CODES = List.of("AAAAAAAAAA", "BBBBBBBBBB");

    /** Keeps the codes; real, so the session round trip is exercised. */
    @Spy
    private PendingRecoveryCodes pendingRecoveryCodes = new PendingRecoveryCodes();

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** The current request. */
    private MockHttpServletRequest request;

    /** The current response. */
    private MockHttpServletResponse response;

    /** Controller under test. */
    private RecoveryCodesPageController controller;

    /**
     * Builds the controller over a request of a signed-in session.
     */
    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest("GET", RecoveryCodesPageController.RECOVERY_CODES_PATH);
        response = new MockHttpServletResponse();
        controller = new RecoveryCodesPageController(pendingRecoveryCodes, pageRenderer, request, response);
    }

    /**
     * Verifies that the pending codes are rendered once, with a link that resumes the interrupted request.
     */
    @Test
    void recoveryCodesPage_whenCodesArePending_rendersThemOnceAndResumesTheSavedRequest() {
        final var interrupted = new MockHttpServletRequest("GET", "/oauth2/authorize");
        interrupted.setQueryString("client_id=client");
        interrupted.setSession(request.getSession(true));
        new HttpSessionRequestCache().saveRequest(interrupted, response);
        pendingRecoveryCodes.save(request, CODES);
        final var page = ResponseEntity.ok("<html></html>");
        when(pageRenderer.render(eq(RecoveryCodesPageController.VIEW_NAME), anyMap())).thenReturn(page);

        assertSame(page, controller.recoveryCodesPage());

        final var model = renderedModel();
        assertEquals(CODES, model.get(RecoveryCodesPageController.CODES_ATTRIBUTE));
        assertTrue(((String) model.get(RecoveryCodesPageController.CONTINUE_ATTRIBUTE))
                .contains("/oauth2/authorize?client_id=client"));
        assertTrue(pendingRecoveryCodes.take(request).isEmpty());
    }

    /**
     * Verifies that, with nothing pending and nothing to resume, the page shows no code and continues to the root.
     */
    @Test
    void recoveryCodesPage_whenNothingIsPending_rendersNoCodeAndContinuesToTheRoot() {
        controller.recoveryCodesPage();

        final var model = renderedModel();
        assertEquals(List.of(), model.get(RecoveryCodesPageController.CODES_ATTRIBUTE));
        assertEquals(RecoveryCodesPageController.DEFAULT_CONTINUE_URL,
                model.get(RecoveryCodesPageController.CONTINUE_ATTRIBUTE));
    }

    /**
     * Gets the model the page was rendered with.
     *
     * @return the model.
     */
    private Map<String, ?> renderedModel() {
        final var captor = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq(RecoveryCodesPageController.VIEW_NAME), captor.capture());
        return captor.getValue();
    }
}
