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

package com.irurueta.authserver.authorization.api.web.logout;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

/**
 * Unit tests of {@link LogoutController}.
 */
@ExtendWith(MockitoExtension.class)
class LogoutControllerTest {

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Controller under test. */
    @InjectMocks
    private LogoutController controller;

    /**
     * Verifies that the confirmation page is rendered from its template, with no model of its own.
     */
    @Test
    void logoutPage_whenRequested_rendersTheConfirmationPage() {
        final var page = ResponseEntity.ok("<html></html>");
        when(pageRenderer.render(LogoutController.VIEW_NAME, Map.of())).thenReturn(page);

        assertSame(page, controller.logoutPage());
    }
}
