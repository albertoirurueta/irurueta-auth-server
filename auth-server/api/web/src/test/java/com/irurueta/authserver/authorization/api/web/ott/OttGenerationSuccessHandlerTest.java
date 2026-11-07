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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.ott.OneTimeCodeRequestResult;
import com.irurueta.authserver.authorization.application.ott.OttDestination;
import com.irurueta.authserver.authorization.application.ott.RequestOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.ott.ResolveOttDestinationUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
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
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link OttGenerationSuccessHandler}. */
@ExtendWith(MockitoExtension.class)
class OttGenerationSuccessHandlerTest {

    /** Value of the token Spring generated. */
    private static final String TOKEN_VALUE = "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c";

    /** Lifetime of a code. */
    private static final Duration CODE_TTL = Duration.ofMinutes(10);

    /** Lifetime of a link. */
    private static final Duration LINK_TTL = Duration.ofMinutes(15);

    /** Length of a code. */
    private static final int CODE_LENGTH = 6;

    /** Attempts tolerated. */
    private static final int MAX_ATTEMPTS = 5;

    /** Address the mail is sent to. */
    private static final String ADDRESS = "alice@example.com";

    /** Starts a numeric code. */
    @Mock
    private RequestOneTimeCodeUseCase requestOneTimeCodeUseCase;

    /** Finds where a token goes. */
    @Mock
    private ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Delivers the link. */
    @Mock
    private OttDelivery ottDelivery;

    /** Store of the link tokens. */
    @Mock
    private OneTimeTokenService oneTimeTokenService;

    /** Builds the link. */
    @Mock
    private OttLinkFactory linkFactory;

    /** Handler under test. */
    private OttGenerationSuccessHandler handler;

    /** The request. */
    private MockHttpServletRequest request;

    /** The response. */
    private MockHttpServletResponse response;

    /** Creates the handler over a real policy. */
    @BeforeEach
    void setUp() {
        handler = new OttGenerationSuccessHandler(requestOneTimeCodeUseCase, resolveOttDestinationUseCase,
                ottDelivery, oneTimeTokenService, new OttPolicy(CODE_LENGTH, CODE_TTL, LINK_TTL, MAX_ATTEMPTS),
                linkFactory);
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
        final var discarded = ArgumentCaptor.<OneTimeTokenAuthenticationToken>captor();
        verify(oneTimeTokenService).consume(discarded.capture());
        assertEquals(TOKEN_VALUE, discarded.getValue().getTokenValue());
        final var pending = PendingOtt.of(request).orElseThrow();
        assertEquals(binding.getValue(), pending.bindingId());
        assertEquals("alice", pending.identifier());
        assertEquals(OttKind.CODE, pending.kind());
        assertEquals(OttChannel.SMS, pending.channel());
        assertEquals("/login/ott", response.getRedirectedUrl());
        verifyNoInteractions(ottDelivery);
    }

    /** A code request as a second factor of the signed-in user is started for that purpose. */
    @Test
    void handle_whenASecondFactorCodeIsRequested_startsItForThatPurpose() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", "x", AuthorityUtils.NO_AUTHORITIES));
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        when(requestOneTimeCodeUseCase.execute(eq("alice"), eq(OttChannel.EMAIL), eq(OttPurpose.SECOND_FACTOR),
                anyString())).thenReturn(new OneTimeCodeRequestResult(true, CODE_TTL));

        handler.handle(request, response, token("alice"));

        assertEquals(OttPurpose.SECOND_FACTOR, PendingOtt.of(request).orElseThrow().purpose());
    }

    /** A link request delivers the confirmation link by e-mail and keeps the token. */
    @Test
    void handle_whenALinkIsRequested_deliversTheConfirmationLinkByEmail() throws Exception {
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        final var link = URI.create("https://auth.example.com/login/ott/confirm?token=" + TOKEN_VALUE);
        when(resolveOttDestinationUseCase.execute("alice", OttChannel.EMAIL))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.EMAIL, ADDRESS)));
        when(linkFactory.confirmationLink(TOKEN_VALUE)).thenReturn(link);

        handler.handle(request, response, token("alice"));

        verify(ottDelivery).deliverLink(OttChannel.EMAIL, ADDRESS, link, LINK_TTL);
        verifyNoInteractions(requestOneTimeCodeUseCase, oneTimeTokenService);
        assertEquals(OttKind.LINK, PendingOtt.of(request).orElseThrow().kind());
        assertEquals("/login/ott", response.getRedirectedUrl());
    }

    /** The marker of a second-factor link is not part of the identifier. */
    @Test
    void handle_whenASecondFactorLinkIsRequested_resolvesTheUnmarkedIdentifier() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", "x", AuthorityUtils.NO_AUTHORITIES));
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        when(resolveOttDestinationUseCase.execute("alice", OttChannel.EMAIL)).thenReturn(Optional.empty());

        handler.handle(request, response, token(LinkTokenUsername.forLink("alice", true)));

        assertEquals("alice", PendingOtt.of(request).orElseThrow().identifier());
    }

    /** An identifier with nowhere to deliver to gets the same redirect and nothing is sent. */
    @Test
    void handle_whenThereIsNoDestination_stillRedirectsAndSendsNothing() throws Exception {
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        when(resolveOttDestinationUseCase.execute("ghost", OttChannel.EMAIL)).thenReturn(Optional.empty());

        handler.handle(request, response, token("ghost"));

        verifyNoInteractions(ottDelivery);
        assertNotNull(PendingOtt.of(request).orElse(null));
        assertEquals("/login/ott", response.getRedirectedUrl());
    }

    /** A delivery that fails is answered like any other. */
    @Test
    void handle_whenTheDeliveryFails_stillRedirects() throws Exception {
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");
        when(resolveOttDestinationUseCase.execute("alice", OttChannel.EMAIL))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.EMAIL, ADDRESS)));
        when(linkFactory.confirmationLink(TOKEN_VALUE)).thenReturn(URI.create("https://auth.example.com/x"));
        doThrow(new OttDeliveryException("down", new IllegalStateException())).when(ottDelivery)
                .deliverLink(any(), anyString(), any(), any());

        handler.handle(request, response, token("alice"));

        assertEquals("/login/ott", response.getRedirectedUrl());
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
