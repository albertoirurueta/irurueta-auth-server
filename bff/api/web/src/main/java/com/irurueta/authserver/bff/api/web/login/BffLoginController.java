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
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
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

    /**
     * Session attribute where {@code HttpSessionRequestCache} keeps the saved request (the constant of that class is
     * not public); the success handler of the OAuth2 login reads it and redirects there.
     */
    static final String SAVED_REQUEST_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

    /** Decides which {@code returnTo} values are safe. */
    private final ReturnToValidator returnToValidator;

    /** The current request, injected as a thread-bound proxy. */
    private final HttpServletRequest request;

    // tag::bff-login[]
    /**
     * Validates {@code returnTo}, stores it as the saved request of the session, so that the success handler of the
     * OAuth2 login sends the browser there, and redirects to the authorization request.
     *
     * @param returnTo relative path to return to after the login; the root of the application when absent.
     * @return a redirect to the authorization request.
     * @throws ResponseStatusException answered 400 when {@code returnTo} is not an allowed relative path.
     */
    @Override
    public ResponseEntity<Void> login(final String returnTo) {
        final var target = returnTo == null || returnTo.isBlank() ? DEFAULT_RETURN_TO : returnTo;
        if (!returnToValidator.isAllowed(target)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "returnTo is not an allowed relative path");
        }
        request.getSession().setAttribute(SAVED_REQUEST_ATTRIBUTE, savedRequest(target));
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(AUTHORIZATION_PATH)).build();
    }
    // end::bff-login[]

    /**
     * Builds the saved request pointing to {@code target} on the host the browser used to reach the BFF.
     *
     * @param target an allowed relative path, with an optional query string.
     * @return the saved request.
     */
    private DefaultSavedRequest savedRequest(final String target) {
        final var fragment = target.indexOf('#');
        final var withoutFragment = fragment >= 0 ? target.substring(0, fragment) : target;
        final var query = withoutFragment.indexOf('?');
        final var builder = new DefaultSavedRequest.Builder()
                .setScheme(request.getScheme())
                .setServerName(request.getServerName())
                .setServerPort(request.getServerPort())
                .setMethod("GET");
        if (query >= 0) {
            builder.setRequestURI(withoutFragment.substring(0, query))
                    .setQueryString(withoutFragment.substring(query + 1));
        } else {
            builder.setRequestURI(withoutFragment);
        }
        return builder.build();
    }
}
