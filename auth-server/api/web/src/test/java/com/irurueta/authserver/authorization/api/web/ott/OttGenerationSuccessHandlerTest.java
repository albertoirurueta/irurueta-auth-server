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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.ott.OneTimeCodeRequestResult;
import com.irurueta.authserver.authorization.application.ott.RequestMagicLinkUseCase;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link OttGenerationSuccessHandler}. */
@ExtendWith(MockitoExtension.class)
class OttGenerationSuccessHandlerTest {

    /** Value of the token Spring generated. */
    private static final String TOKEN_VALUE = "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c";

    /** Lifetime of a code. */
    private static final Duration CODE_TTL = Duration.ofMinutes(10);

    /** Path of the page that says to check the inbox. */
    private static final String CODE_PAGE = "/login/ott";

    /** Starts a numeric code. */
    @Mock
    private RequestOneTimeCodeUseCase requestOneTimeCodeUseCase;

    /** Requests the delivery of a link. */
    @Mock
    private RequestMagicLinkUseCase requestMagicLinkUseCase;

    /** Store of the link tokens. */
    @Mock
    private OneTimeTokenService oneTimeTokenService;

    /** Builds the link. */
    @Mock
    private OttLinkFactory linkFactory;

    /** Decides which channels may be the second factor. */
    @Mock
    private OttSecondFactorChannels secondFactorChannels;

    /** Handler under test. */
    private OttGenerationSuccessHandler handler;

    /** The request. */
    private MockHttpServletRequest request;

    /** The response. */
    private MockHttpServletResponse response;

    /** Creates the handler. */
    @BeforeEach
    void setUp() {
        handler = new OttGenerationSuccessHandler(requestOneTimeCodeUseCase, requestMagicLinkUseCase,
                oneTimeTokenService, linkFactory, secondFactorChannels);
        request = new MockHttpServletRequest("POST", "/ott/generate");
        response = new MockHttpServletResponse();
    }

    /** Clears the security context. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** A code request stores the code bound to the session, discards the unused token and redirects. */
    @Test
    void handle_whenACodeIsRequested_startsTheCodeBoundToTheSessionAndRedirects() throws Exception {
        request.setParameter(OttGenerationParameters.CHANNEL_PARAMETER, "sms");
        when(requestOneTimeCodeUseCase.execute(eq("alice"), eq(OttChannel.SMS), eq(OttPurpose.LOGIN), anyString()))
                .thenReturn(new OneTimeCodeRequestResult(true, CODE_TTL));

        handler.handle(request, response, token("alice"));

        final var binding = ArgumentCaptor.<String>captor();
        verify(requestOneTimeCodeUseCase).execute(eq("alice"), eq(OttChannel.SMS), eq(OttPurpose.LOGIN),
                binding.capture());
        assertTokenDiscarded();
        final var pending = PendingOtt.of(request).orElseThrow();
        assertEquals(binding.getValue(), pending.bindingId());
        assertEquals("alice", pending.identifier());
        assertEquals(OttKind.CODE, pending.kind());
        assertEquals(OttChannel.SMS, pending.channel());
        assertEquals(CODE_PAGE, response.getRedirectedUrl());
        verifyNoInteractions(requestMagicLinkUseCase, secondFactorChannels);
    }

    /** A code request as a second factor through an allowed channel is started for that purpose. */
    @Test
    void handle_whenAnAllowedSecondFactorCodeIsRequested_startsItForThatPurpose() throws Exception {
        final var current = signIn("alice");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        when(secondFactorChannels.isAllowed(current, OttChannel.EMAIL)).thenReturn(true);
        when(requestOneTimeCodeUseCase.execute(eq("alice"), eq(OttChannel.EMAIL), eq(OttPurpose.SECOND_FACTOR),
                anyString())).thenReturn(new OneTimeCodeRequestResult(true, CODE_TTL));

        handler.handle(request, response, token("alice"));

        assertEquals(OttPurpose.SECOND_FACTOR, PendingOtt.of(request).orElseThrow().purpose());
    }

    /**
     * A second-factor code through a channel the user may not use (the one that signed the user in, or e-mail for a
     * user with another confirmed second factor) is answered the same, but nothing is stored or sent.
     */
    @Test
    void handle_whenASecondFactorCodeChannelIsNotAllowed_redirectsTheSameAndSendsNothing() throws Exception {
        final var current = signIn("alice");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        when(secondFactorChannels.isAllowed(current, OttChannel.EMAIL)).thenReturn(false);

        handler.handle(request, response, token("alice"));

        verifyNoInteractions(requestOneTimeCodeUseCase, requestMagicLinkUseCase);
        assertTokenDiscarded();
        assertEquals(OttPurpose.SECOND_FACTOR, PendingOtt.of(request).orElseThrow().purpose());
        assertEquals(CODE_PAGE, response.getRedirectedUrl());
    }

    /** A link request asks for the delivery of the confirmation link and keeps the token. */
    @Test
    void handle_whenALinkIsRequested_requestsTheConfirmationLink() throws Exception {
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        final var link = URI.create("https://auth.example.com/login/ott/confirm?token=" + TOKEN_VALUE);
        when(linkFactory.confirmationLink(TOKEN_VALUE)).thenReturn(link);

        handler.handle(request, response, token("alice"));

        verify(requestMagicLinkUseCase).execute("alice", link);
        verifyNoInteractions(requestOneTimeCodeUseCase, oneTimeTokenService);
        assertEquals(OttKind.LINK, PendingOtt.of(request).orElseThrow().kind());
        assertEquals(CODE_PAGE, response.getRedirectedUrl());
    }

    /** The marker of an allowed second-factor link is not part of the identifier the link is requested for. */
    @Test
    void handle_whenAnAllowedSecondFactorLinkIsRequested_requestsItForTheUnmarkedIdentifier() throws Exception {
        final var current = signIn("alice");
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        final var link = URI.create("https://auth.example.com/login/ott/confirm?token=" + TOKEN_VALUE);
        when(secondFactorChannels.isAllowed(current, OttChannel.EMAIL)).thenReturn(true);
        when(linkFactory.confirmationLink(TOKEN_VALUE)).thenReturn(link);

        handler.handle(request, response, token(LinkTokenUsername.forLink("alice", true)));

        verify(requestMagicLinkUseCase).execute("alice", link);
        assertEquals("alice", PendingOtt.of(request).orElseThrow().identifier());
    }

    /** A second-factor link the user may not use is answered the same, its token discarded and nothing sent. */
    @Test
    void handle_whenASecondFactorLinkIsNotAllowed_redirectsTheSameAndSendsNothing() throws Exception {
        final var current = signIn("alice");
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        when(secondFactorChannels.isAllowed(current, OttChannel.EMAIL)).thenReturn(false);

        handler.handle(request, response, token(LinkTokenUsername.forLink("alice", true)));

        verifyNoInteractions(requestMagicLinkUseCase, requestOneTimeCodeUseCase, linkFactory);
        assertTokenDiscarded();
        assertEquals(CODE_PAGE, response.getRedirectedUrl());
    }

    /**
     * A second-factor link of a user name too long to fit next to the marker would never match its user: it is
     * answered the same, its token discarded and nothing sent, whatever the channels allowed.
     */
    @Test
    void handle_whenTheUserNameIsTooLongForASecondFactorLink_redirectsTheSameAndSendsNothing() throws Exception {
        final var longName = "a".repeat(LinkTokenUsername.MAX_LENGTH);
        signIn(longName);
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");

        handler.handle(request, response, token(LinkTokenUsername.forLink(longName, true)));

        verifyNoInteractions(requestMagicLinkUseCase, requestOneTimeCodeUseCase, linkFactory, secondFactorChannels);
        assertTokenDiscarded();
        assertEquals(CODE_PAGE, response.getRedirectedUrl());
    }

    /**
     * Signs a user in.
     *
     * @param username the name of the user.
     * @return the authentication of the user.
     */
    private static Authentication signIn(final String username) {
        final var current = UsernamePasswordAuthenticationToken.authenticated(username, "x",
                AuthorityUtils.NO_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(current);
        return current;
    }

    /**
     * Checks that the token Spring generated was consumed, so it can never be used.
     */
    private void assertTokenDiscarded() {
        final var discarded = ArgumentCaptor.<OneTimeTokenAuthenticationToken>captor();
        verify(oneTimeTokenService).consume(discarded.capture());
        assertEquals(TOKEN_VALUE, discarded.getValue().getTokenValue());
    }

    /**
     * Builds the token Spring generated.
     *
     * @param username the stored user name.
     * @return the token.
     */
    private static DefaultOneTimeToken token(final String username) {
        return new DefaultOneTimeToken(TOKEN_VALUE, username, Instant.EPOCH.plusSeconds(1));
    }
}
