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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.DeviceVerificationPageApi;
import java.util.HashMap;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

/**
 * Serves the device verification page, as the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml}
 * describes it through the generated {@link DeviceVerificationPageApi}: the form where the user types the code the
 * device shows. The form posts to the framework's own endpoint ({@code POST /oauth2/device_verification}); a request
 * that already carries a code never reaches this controller, because that endpoint answers it. The page is also where
 * the endpoint sends the browser back to, with {@code ?error} when the attempt failed and {@code ?success} when the
 * device was approved.
 */
@Controller
@RequiredArgsConstructor
public class DeviceVerificationController implements DeviceVerificationPageApi {

    /** Path of the page, and of the verification endpoint, taken from the contract. */
    public static final String VERIFICATION_PATH = PATH_DEVICE_VERIFICATION_PAGE;

    /** Name of the parameter that tells the page that the device was just approved. */
    public static final String SUCCESS_PARAMETER = "success";

    /** Name of the template of the page. */
    static final String VIEW_NAME = "device-verification";

    /** Name of the model attribute that holds the code to prefill. */
    static final String USER_CODE_ATTRIBUTE = "userCode";

    /** Name of the model attribute that tells whether the previous attempt failed. */
    static final String ERROR_ATTRIBUTE = "failed";

    /** Name of the model attribute that tells whether the device was just approved. */
    static final String SUCCESS_ATTRIBUTE = "approved";

    /** Shape of a user code worth prefilling: letters, digits and dashes. */
    private static final Pattern PLAUSIBLE_CODE = Pattern.compile("[A-Za-z0-9-]{1,32}");

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    // tag::device-verification-controller[]
    /**
     * Renders the device verification page.
     *
     * @param userCode a code to prefill, ignored unless it looks like a user code.
     * @param error    present when the previous attempt failed.
     * @param success  present when the device was just approved.
     * @return the page.
     */
    @Override
    public ResponseEntity<String> deviceVerificationPage(final String userCode, final String error,
            final String success) {
        final var model = new HashMap<String, Object>();
        model.put(ERROR_ATTRIBUTE, error != null);
        model.put(SUCCESS_ATTRIBUTE, success != null);
        if (userCode != null && PLAUSIBLE_CODE.matcher(userCode).matches()) {
            model.put(USER_CODE_ATTRIBUTE, userCode);
        }
        return pageRenderer.render(VIEW_NAME, model);
    }
    // end::device-verification-controller[]
}
