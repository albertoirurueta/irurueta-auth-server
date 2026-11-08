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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

/**
 * Unit tests of {@link DeviceVerificationController}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceVerificationControllerTest {

    /** A plausible user code. */
    private static final String USER_CODE = "BCDF-GHJK";

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Controller under test. */
    @InjectMocks
    private DeviceVerificationController controller;

    /**
     * Verifies that the path is the contract's one.
     */
    @Test
    void verificationPath_isTheContractPath() {
        assertEquals("/oauth2/device_verification", DeviceVerificationController.VERIFICATION_PATH);
    }

    /**
     * Verifies that the plain page has neither a code, nor an error, nor a confirmation.
     */
    @Test
    void deviceVerificationPage_whenNothingIsAsked_rendersTheForm() {
        final var model = render(null, null, null);

        assertEquals(Map.of("failed", false, "approved", false), model);
    }

    /**
     * Verifies that a plausible code is prefilled.
     */
    @Test
    void deviceVerificationPage_whenTheCodeIsPlausible_prefillsIt() {
        final var model = render(USER_CODE, null, null);

        assertEquals(USER_CODE, model.get(DeviceVerificationController.USER_CODE_ATTRIBUTE));
    }

    /**
     * Verifies that a value that is not a user code is ignored.
     */
    @Test
    void deviceVerificationPage_whenTheCodeIsNotPlausible_ignoresIt() {
        final var model = render("<script>alert(1)</script>", null, null);

        assertEquals(Map.of("failed", false, "approved", false), model);
    }

    /**
     * Verifies that the error flag is shown, whatever its value.
     */
    @Test
    void deviceVerificationPage_whenErrorIsPresent_showsTheError() {
        assertEquals(true, render(null, "", null).get(DeviceVerificationController.ERROR_ATTRIBUTE));
    }

    /**
     * Verifies that the confirmation is shown, whatever its value.
     */
    @Test
    void deviceVerificationPage_whenSuccessIsPresent_showsTheConfirmation() {
        assertEquals(true, render(null, null, "").get(DeviceVerificationController.SUCCESS_ATTRIBUTE));
    }

    /**
     * Renders the page and returns the model it was rendered with.
     *
     * @param userCode the code parameter.
     * @param error    the error parameter.
     * @param success  the success parameter.
     * @return the model.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> render(final String userCode, final String error, final String success) {
        final var page = ResponseEntity.ok("<html></html>");
        final var captor = ArgumentCaptor.<Map<String, ?>>captor();
        when(pageRenderer.render(org.mockito.ArgumentMatchers.eq(DeviceVerificationController.VIEW_NAME),
                captor.capture())).thenReturn(page);

        assertSame(page, controller.deviceVerificationPage(userCode, error, success));

        verify(pageRenderer).render(DeviceVerificationController.VIEW_NAME, captor.getValue());
        return (Map<String, Object>) captor.getValue();
    }
}
