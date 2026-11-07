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
import com.irurueta.authserver.authorization.application.ott.RequestMagicLinkUseCase;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
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
 * does not tell whether the account exists. The use cases only request the delivery, which happens after their
 * transaction commits and off the request thread, so neither a slow mail server or SMS gateway nor a delivery failure
 * shows in the response.
 *
 * <p>A token asked for as a second factor is delivered only through a channel {@link OttSecondFactorChannels} allows
 * for the signed-in user (never the channel that signed the user in, and e-mail only to a user without another
 * confirmed second factor), and a second-factor link only for a user name that fits next to the marker of
 * {@link LinkTokenUsername}. Any other request is answered the same, but its token is discarded and nothing is sent.
 */
@RequiredArgsConstructor
public class OttGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

    /** Starts the numeric code of a channel. */
    private final RequestOneTimeCodeUseCase requestOneTimeCodeUseCase;

    /** Requests the delivery of a magic link. */
    private final RequestMagicLinkUseCase requestMagicLinkUseCase;

    /** Store of the link tokens, which the code requests discard their unused token from. */
    private final OneTimeTokenService oneTimeTokenService;

    /** Builds the magic link. */
    private final OttLinkFactory linkFactory;

    /** Decides which channels may be the second factor of the signed-in user. */
    private final OttSecondFactorChannels secondFactorChannels;

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
        final var current = SecurityContextHolder.getContext().getAuthentication();
        final var parameters = OttGenerationParameters.from(request, current);
        final var identifier = LinkTokenUsername.identifierOf(token.getUsername());
        final var bindingId = UUID.randomUUID().toString();
        final var deliverable = isDeliverable(parameters, current);
        if (parameters.kind() == OttKind.LINK && deliverable) {
            requestMagicLinkUseCase.execute(identifier, linkFactory.confirmationLink(token.getTokenValue()));
        } else {
            // a code, or a link that is not sent, never uses the token of the stock service
            oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(token.getTokenValue()));
            if (deliverable) {
                requestOneTimeCodeUseCase.execute(identifier, parameters.channel(), parameters.purpose(), bindingId);
            }
        }
        new PendingOtt(identifier, bindingId, parameters.kind(), parameters.purpose(), parameters.channel())
                .saveTo(request.getSession());
        redirectStrategy.sendRedirect(request, response, OneTimeTokenPageApi.PATH_OTT_CODE_PAGE);
    }

    /**
     * Tells whether a token may be delivered: always for a sign-in; for a second factor only through a channel the
     * signed-in user may use, and a link only when the user name fits the token store with its marker.
     *
     * @param parameters what the request asks for.
     * @param current    the authentication of the request.
     * @return {@code true} when the token may be delivered.
     */
    private boolean isDeliverable(final OttGenerationParameters parameters, final Authentication current) {
        if (parameters.purpose() != OttPurpose.SECOND_FACTOR) {
            return true;
        }
        if (parameters.kind() == OttKind.LINK && !LinkTokenUsername.fitsSecondFactorLink(current.getName())) {
            return false;
        }
        return secondFactorChannels.isAllowed(current, parameters.channel());
    }
}
