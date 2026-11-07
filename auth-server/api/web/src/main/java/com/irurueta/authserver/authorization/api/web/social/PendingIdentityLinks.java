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
package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

// tag::social-pending-link[]
/**
 * Keeps the link marker ({@link PendingIdentityLink}) of the explicit link flow: the identities page records it in the
 * session before sending the browser to the provider, and the user services consume it when the provider sends the
 * user back. The marker is used once and only within {@link #LIFETIME}, only for the provider it names and only while
 * the session is still signed in as the account that asked; otherwise the sign-in goes on as an ordinary one. When
 * the marker is consumed, the authentication of the session is kept in a request attribute, so the success handler can
 * put it back: linking never switches the session to another principal.
 */
@Component
@RequiredArgsConstructor
public class PendingIdentityLinks {

    /** How long a link marker stays usable. */
    public static final Duration LIFETIME = Duration.ofMinutes(5);

    /** Session attribute of the marker. */
    static final String SESSION_ATTRIBUTE = PendingIdentityLinks.class.getName() + ".PENDING";

    /** Request attribute of the authentication the session had when the marker was consumed. */
    static final String LINKED_ATTRIBUTE = PendingIdentityLinks.class.getName() + ".LINKED";

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Records that the next sign-in with a provider links its identity to the signed-in account.
     *
     * @param session  the session of the signed-in user.
     * @param provider the provider of the identity to link.
     * @param userId   identifier of the signed-in account.
     * @param username name of the signed-in account.
     */
    public void begin(final HttpSession session, final IdentityProvider provider, final UUID userId,
                      final String username) {
        session.setAttribute(SESSION_ATTRIBUTE,
                new PendingIdentityLink(provider.id(), userId, username, clock.instant().plus(LIFETIME)));
    }

    /**
     * Consumes the marker of the current request, if it is usable for a sign-in with a provider. The marker is removed
     * whether or not it is usable.
     *
     * @param provider the provider the user just signed in with.
     * @return the marker, or empty when there is none, it expired, it names another provider or the session is no
     *         longer signed in as the account that asked.
     */
    public Optional<PendingIdentityLink> consume(final IdentityProvider provider) {
        if (!(RequestContextHolder.getRequestAttributes() instanceof final ServletRequestAttributes attributes)) {
            return Optional.empty();
        }
        final var request = attributes.getRequest();
        final var session = request.getSession(false);
        if (session == null || !(session.getAttribute(SESSION_ATTRIBUTE) instanceof final PendingIdentityLink link)) {
            return Optional.empty();
        }
        session.removeAttribute(SESSION_ATTRIBUTE);
        final var current = SecurityContextHolder.getContext().getAuthentication();
        if (!provider.id().equals(link.providerId()) || clock.instant().isAfter(link.expiresAt())
                || !MfaAuthorizationManager.isUser(current) || !link.username().equals(current.getName())) {
            return Optional.empty();
        }
        request.setAttribute(LINKED_ATTRIBUTE, current);
        return Optional.of(link);
    }

    /**
     * Finds the authentication a request had when it linked an identity.
     *
     * @param request the request of the provider's answer.
     * @return the authentication to keep, or empty when the request was not a link.
     */
    public Optional<Authentication> linkedBy(final HttpServletRequest request) {
        return request.getAttribute(LINKED_ATTRIBUTE) instanceof final Authentication authentication
                ? Optional.of(authentication) : Optional.empty();
    }
}
// end::social-pending-link[]
