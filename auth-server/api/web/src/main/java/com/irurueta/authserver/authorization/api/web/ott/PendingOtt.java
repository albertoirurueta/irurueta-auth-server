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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Optional;

/**
 * The one-time token a browser has asked for and not used yet, kept in its session: for whom, through which channel,
 * of which kind and for what purpose, and the binding id the numeric code was stored with. A code only works in the
 * browser that holds its binding id, which is what makes a code typed in another browser worthless. The session holds
 * one pending token: asking again replaces it (and so invalidates the previous code).
 *
 * @param identifier identifier (the user name) the token was requested for, as the user typed it.
 * @param bindingId  random identifier that ties the numeric code to this session.
 * @param kind       whether the token is a numeric code or a magic link.
 * @param purpose    whether the token signs the user in or is a second factor.
 * @param channel    channel the token is delivered through.
 */
public record PendingOtt(String identifier, String bindingId, OttKind kind, OttPurpose purpose, OttChannel channel)
        implements Serializable {

    /** Serialization version. */
    private static final long serialVersionUID = 1L;

    /** Name of the session attribute that holds the pending token. */
    static final String ATTRIBUTE = PendingOtt.class.getName();

    /**
     * Keeps this pending token in a session, replacing the previous one.
     *
     * @param session the session.
     */
    public void saveTo(final HttpSession session) {
        session.setAttribute(ATTRIBUTE, this);
    }

    /**
     * Finds the pending token of the session of a request, without creating a session.
     *
     * @param request the request.
     * @return the pending token, or empty when the request has no session or the session holds none.
     */
    public static Optional<PendingOtt> of(final HttpServletRequest request) {
        final var session = request.getSession(false);
        final var value = session == null ? null : session.getAttribute(ATTRIBUTE);
        return value instanceof final PendingOtt pending ? Optional.of(pending) : Optional.empty();
    }

    /**
     * Forgets the pending token of the session of a request, once it has been used.
     *
     * @param request the request.
     */
    public static void clear(final HttpServletRequest request) {
        final var session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(ATTRIBUTE);
        }
    }

    /**
     * Describes the pending token without the binding id, which authorizes a code.
     *
     * @return the kind, purpose and channel only.
     */
    @Override
    public String toString() {
        return "PendingOtt[kind=" + kind + ", purpose=" + purpose + ", channel=" + channel + "]";
    }
}
