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

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Keeps, in the session, the recovery codes generated when an authenticator app is enrolled during the sign-in, from
 * the post that confirms it until the page that shows them once ({@link RecoveryCodesPageController}), which takes
 * them out of the session.
 */
@Component
public class PendingRecoveryCodes {

    /** Name of the session attribute that holds the codes. */
    static final String ATTRIBUTE = PendingRecoveryCodes.class.getName() + ".CODES";

    /**
     * Stores the codes in the session of a request.
     *
     * @param request the request.
     * @param codes   the codes in clear text.
     */
    public void save(final HttpServletRequest request, final List<String> codes) {
        request.getSession().setAttribute(ATTRIBUTE, new ArrayList<>(codes));
    }

    /**
     * Tells whether the session of a request holds codes not shown yet.
     *
     * @param request the request.
     * @return {@code true} when there are codes waiting to be shown.
     */
    public boolean isPending(final HttpServletRequest request) {
        final var session = request.getSession(false);
        return session != null && session.getAttribute(ATTRIBUTE) != null;
    }

    /**
     * Takes the codes out of the session of a request, so they are shown only once.
     *
     * @param request the request.
     * @return the codes; empty when there are none.
     */
    public List<String> take(final HttpServletRequest request) {
        final var session = request.getSession(false);
        if (session == null) {
            return List.of();
        }
        final var stored = session.getAttribute(ATTRIBUTE);
        session.removeAttribute(ATTRIBUTE);
        if (!(stored instanceof List<?> codes)) {
            return List.of();
        }
        return codes.stream().map(String::valueOf).toList();
    }
}
