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

package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.SecondFactorPageApi;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;

/**
 * Serves the second-factor page, as the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml}
 * describes it through the generated {@link SecondFactorPageApi}, supplying the ordered fragments of the second
 * factors, the model attributes each of them contributes for the signed-in user and the outcome of the last attempt to
 * the template.
 */
@Controller
public class SecondFactorController implements SecondFactorPageApi {

    /** Path of the second-factor page, taken from the contract. */
    public static final String SECOND_FACTOR_PATH = PATH_SECOND_FACTOR_PAGE;

    /** Key of the message shown when a code is wrong. */
    public static final String GENERIC_ERROR = "secondFactor.error.generic";

    /** Key of the message shown when the second factor is locked. */
    public static final String LOCKED_ERROR = "secondFactor.error.locked";

    /** Name of the second-factor template. */
    static final String VIEW_NAME = "second-factor";

    /** Name of the model attribute that holds the fragments of the second factors. */
    static final String FRAGMENTS_ATTRIBUTE = "fragments";

    /** Name of the model attribute that holds the key of the message of a failed attempt. */
    static final String ERROR_MESSAGE_ATTRIBUTE = "errorMessageKey";

    /** Fragments contributed by the second factors, sorted by order. */
    private final List<SecondFactorFragment> fragments;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, whose session holds the last failure. */
    private final HttpServletRequest request;

    /**
     * Creates the controller.
     *
     * @param factors      fragments contributed by the second factors.
     * @param pageRenderer renderer of the page.
     * @param request      the current request.
     */
    public SecondFactorController(final List<SecondFactorFragment> factors, final PageRenderer pageRenderer,
            final HttpServletRequest request) {
        this.fragments = factors.stream().sorted(Comparator.comparingInt(SecondFactorFragment::order)).toList();
        this.pageRenderer = pageRenderer;
        this.request = request;
    }

    // tag::mfa-second-factor-page[]
    /**
     * Renders the second-factor page.
     *
     * @param error present (even if empty) when the previous attempt failed.
     * @return the second-factor page.
     */
    @Override
    public ResponseEntity<String> secondFactorPage(final String error) {
        final var model = new HashMap<String, Object>();
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        fragments.forEach(fragment -> model.putAll(fragment.modelAttributes(authentication)));
        model.put(FRAGMENTS_ATTRIBUTE, fragments);
        if (error != null) {
            model.put(ERROR_MESSAGE_ATTRIBUTE, lastFailureWasLockout() ? LOCKED_ERROR : GENERIC_ERROR);
        }
        return pageRenderer.render(VIEW_NAME, model);
    }
    // end::mfa-second-factor-page[]

    /**
     * Tells whether the previous attempt failed because the second factor is locked, which Spring Security keeps in
     * the session.
     *
     * @return {@code true} when the session holds a {@link LockedException} as the last failure.
     */
    private boolean lastFailureWasLockout() {
        final var session = request.getSession(false);
        final var failure = session == null ? null : session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        return failure instanceof LockedException;
    }
}
