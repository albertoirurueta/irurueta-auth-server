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

import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.ott.ResolveOttDestinationUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

/**
 * Delivers the token Spring's filter just generated, and answers every request the same way. The token the stock
 * service stored is the one of a magic link; for a numeric code it is discarded, because a code cannot use that store
 * (it is keyed by the token value alone, and a six-digit value collides across users), and
 * {@link RequestOneTimeCodeUseCase} stores the code in its own table, bound to a new binding id kept in the session.
 * Nothing is sent, and nothing differs for the caller, when the identifier is unknown, disabled or has no verified
 * e-mail address or phone: the browser is always redirected to the page that says to check the inbox, so the response
 * does not tell whether the account exists. A delivery that fails is logged without its destination and answered the
 * same.
 */
@Slf4j
@RequiredArgsConstructor
public class OttGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    /** Starts the numeric code of a channel. */
    private final RequestOneTimeCodeUseCase requestOneTimeCodeUseCase;

    /** Finds where a token for an identifier goes. */
    private final ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Delivers the magic link. */
    private final OttDelivery ottDelivery;

    /** Store of the link tokens, which the code requests discard their unused token from. */
    private final OneTimeTokenService oneTimeTokenService;

    /** The rules of one-time tokens, which set the lifetime shown with a link. */
    private final OttPolicy ottPolicy;

    /** Builds the magic link. */
    private final OttLinkFactory linkFactory;

    /** Redirects to the page that says to check the inbox. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * Delivers the token and redirects to the page that says to check the inbox.
     *
     * @param request  the request.
     * @param response the response.
     * @param token    the token Spring's filter generated.
     * @throws IOException if the redirect cannot be sent.
     */
    @Override
    public void handle(final HttpServletRequest request, final HttpServletResponse response, final OneTimeToken token)
            throws IOException {
        final var parameters = OttGenerationParameters.from(request,
                SecurityContextHolder.getContext().getAuthentication());
        final var identifier = LinkTokenUsername.identifierOf(token.getUsername());
        final var bindingId = UUID.randomUUID().toString();
        if (parameters.kind() == OttKind.CODE) {
            oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue()));
            requestOneTimeCodeUseCase.execute(identifier, parameters.channel(), parameters.purpose(), bindingId);
        } else {
            deliverLink(identifier, token);
        }
        new PendingOtt(identifier, bindingId, parameters.kind(), parameters.purpose(), parameters.channel())
                .saveTo(request.getSession());
        redirectStrategy.sendRedirect(request, response, OneTimeTokenPageApi.PATH_OTT_CODE_PAGE);
    }

    /**
     * Sends the magic link of a token to the e-mail address of the account, when there is one.
     *
     * @param identifier the identifier the link was requested for.
     * @param token      the token.
     */
    private void deliverLink(final String identifier, final OneTimeToken token) {
        final var destination = resolveOttDestinationUseCase.execute(identifier, OttChannel.EMAIL).orElse(null);
        if (destination == null) {
            return;
        }
        try {
            ottDelivery.deliverLink(OttChannel.EMAIL, destination.address(),
                    linkFactory.confirmationLink(token.getTokenValue()), ottPolicy.ttl(OttKind.LINK));
        } catch (final OttDeliveryException e) {
            log.warn("A magic link was not delivered: {}", e.getClass().getSimpleName());
        }
    }
}
