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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.RecoveryCodesPageApi;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Controller;

// tag::totp-recovery-codes-page[]
/**
 * Serves the page that shows, once, the recovery codes generated when an authenticator app was enrolled during the
 * sign-in, as the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes it through the
 * generated {@link RecoveryCodesPageApi}. The codes are taken out of the session as the page is rendered, so a reload
 * shows none; its "Continue" button resumes the request the sign-in interrupted (kept by the session request cache),
 * or goes to the root when there is none.
 */
@Controller
@RequiredArgsConstructor
public class RecoveryCodesPageController implements RecoveryCodesPageApi {

    /** Path of the page, taken from the contract. */
    public static final String RECOVERY_CODES_PATH = PATH_RECOVERY_CODES_PAGE;

    /** Name of the template. */
    static final String VIEW_NAME = "recovery-codes";

    /** Name of the model attribute that holds the codes. */
    static final String CODES_ATTRIBUTE = "recoveryCodes";

    /** Name of the model attribute that holds where the "Continue" button goes. */
    static final String CONTINUE_ATTRIBUTE = "continueUrl";

    /** Where the "Continue" button goes when no request is waiting to be resumed. */
    static final String DEFAULT_CONTINUE_URL = "/";

    /** Cache that keeps the interrupted request, shared with the form login and the second-factor entry point. */
    private final RequestCache requestCache = new HttpSessionRequestCache();

    /** Keeps the codes waiting to be shown. */
    private final PendingRecoveryCodes pendingRecoveryCodes;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy. */
    private final HttpServletRequest request;

    /** The current response, injected as a thread-bound proxy. */
    private final HttpServletResponse response;

    /**
     * Renders the page and forgets the codes.
     *
     * @return the recovery codes page.
     */
    @Override
    public ResponseEntity<String> recoveryCodesPage() {
        final var codes = pendingRecoveryCodes.take(request);
        final var saved = requestCache.getRequest(request, response);
        return pageRenderer.render(VIEW_NAME, Map.of(CODES_ATTRIBUTE, codes,
                CONTINUE_ATTRIBUTE, saved == null ? DEFAULT_CONTINUE_URL : saved.getRedirectUrl()));
    }
}
// end::totp-recovery-codes-page[]
