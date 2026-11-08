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

package com.irurueta.authserver.bff.api.web.login;

import com.irurueta.authserver.bff.api.web.v1.generated.api.LoginApi;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Starts the OpenID Connect login, as the contract {@code apis/bff/rest-server/bff-api-v1.yaml} describes it through
 * the generated {@link LoginApi}.
 */
@RestController
@RequiredArgsConstructor
public class BffLoginController implements LoginApi {

    /** Where the browser goes when the login is requested without {@code returnTo}. */
    static final String DEFAULT_RETURN_TO = "/";

    /** Authorization request endpoint of the {@code bff} registration. */
    static final String AUTHORIZATION_PATH = "/oauth2/authorization/bff";

    /** Decides which {@code returnTo} values are safe. */
    private final ReturnToValidator returnToValidator;

    /** The current request, injected as a thread-bound proxy. */
    private final HttpServletRequest request;

    // tag::bff-login[]
    /**
     * Validates {@code returnTo}, keeps it in the session for {@link ReturnToAuthenticationSuccessHandler}, which sends
     * the browser there once the OAuth2 login succeeds, keeps the step-up values (if any) for
     * {@link StepUpAuthorizationRequestResolver}, which adds them to the authorization request, and redirects to the
     * authorization request. The format and range of {@code acrValues} and {@code maxAge} are checked by the generated
     * interface.
     *
     * @param returnTo  relative path to return to after the login; the root of the application when absent.
     * @param acrValues authentication context classes to ask the authorization server for; none when absent.
     * @param maxAge    maximum age, in seconds, of the authentication to ask for; none when absent.
     * @return a redirect to the authorization request.
     * @throws ResponseStatusException answered 400 when {@code returnTo} is not an allowed relative path.
     */
    @Override
    public ResponseEntity<Void> login(final String returnTo, final String acrValues, final Long maxAge) {
        final var target = StringUtils.hasText(returnTo) ? returnTo : DEFAULT_RETURN_TO;
        if (!returnToValidator.isAllowed(target)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "returnTo is not an allowed relative path");
        }
        final var session = request.getSession();
        session.setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE, target);
        if (StringUtils.hasText(acrValues) || maxAge != null) {
            session.setAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE,
                    new StepUpLoginParameters(StringUtils.hasText(acrValues) ? acrValues : null, maxAge));
        } else {
            session.removeAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE);
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(AUTHORIZATION_PATH)).build();
    }
    // end::bff-login[]
}
