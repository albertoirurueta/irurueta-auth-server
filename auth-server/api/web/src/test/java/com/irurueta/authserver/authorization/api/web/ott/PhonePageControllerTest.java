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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.application.sms.ConfirmPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.FindUserPhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.InvalidPhoneNumberException;
import com.irurueta.authserver.authorization.application.sms.PhoneEnrolmentStarted;
import com.irurueta.authserver.authorization.application.sms.RemovePhoneUseCase;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import com.irurueta.authserver.authorization.application.sms.StartPhoneEnrolmentUseCase;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link PhonePageController}. */
@ExtendWith(MockitoExtension.class)
class PhonePageControllerTest {

    /** Address of the client. */
    private static final String ADDRESS = "203.0.113.7";

    /** The number the user types. */
    private static final String TYPED = "600 111 222";

    /** The number, normalized. */
    private static final String E164 = "+34600111222";

    /** The code. */
    private static final String CODE = "123456";

    /** Seconds before another request is allowed. */
    private static final long RETRY_SECONDS = 30L;

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Finds the phone. */
    @Mock
    private FindUserPhoneUseCase findUserPhoneUseCase;

    /** Starts an enrolment. */
    @Mock
    private StartPhoneEnrolmentUseCase startPhoneEnrolmentUseCase;

    /** Confirms an enrolment. */
    @Mock
    private ConfirmPhoneUseCase confirmPhoneUseCase;

    /** Removes the phone. */
    @Mock
    private RemovePhoneUseCase removePhoneUseCase;

    /** The step-up rule. */
    @Mock
    private PhoneSessionStepUp stepUp;

    /** Limits the requests. */
    @Mock
    private OttRateLimiter rateLimiter;

    /** Real mapper. */
    @Spy
    private PhoneDtoMapper phoneDtoMapper = new PhoneDtoMapper();

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** The request. */
    @Mock
    private HttpServletRequest request;

    /** Controller under test. */
    @InjectMocks
    private PhonePageController controller;

    /** Clears the security context a test set. */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /** The page of an account with a phone shows it masked, and is never cached. */
    @Test
    void phonePage_whenThereIsAVerifiedPhone_rendersItMasked() {
        givenAccount();
        when(findUserPhoneUseCase.execute(userId))
                .thenReturn(Optional.of(new UserPhone(userId, new PhoneNumber(E164), Instant.EPOCH)));
        when(pageRenderer.render(eq("account-phone"), anyMap())).thenReturn(ResponseEntity.ok("<html></html>"));

        final var response = controller.phonePage(null);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("<html></html>", response.getBody());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("account-phone"), model.capture());
        assertEquals(Map.of("phone", "+*******1222"), model.getValue());
    }

    /** The page of an account without a phone carries the known status and nothing else. */
    @Test
    void phonePage_whenThereIsNoPhoneAndTheStatusIsKnown_rendersTheStatus() {
        givenAccount();
        when(findUserPhoneUseCase.execute(userId)).thenReturn(Optional.empty());
        when(pageRenderer.render(eq("account-phone"), anyMap())).thenReturn(ResponseEntity.ok(""));

        controller.phonePage("pending");

        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("account-phone"), model.capture());
        assertEquals(Map.of("status", "pending"), model.getValue());
    }

    /** A status the page does not know is ignored. */
    @Test
    void phonePage_whenTheStatusIsUnknown_ignoresIt() {
        givenAccount();
        when(findUserPhoneUseCase.execute(userId)).thenReturn(Optional.empty());
        when(pageRenderer.render(eq("account-phone"), anyMap())).thenReturn(ResponseEntity.ok(""));

        controller.phonePage("<script>");

        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("account-phone"), model.capture());
        assertTrue(model.getValue().isEmpty());
    }

    /** A number is sent a code, and the answer is a redirect with the pending status. */
    @Test
    void startPhoneEnrolmentPage_whenTheNumberIsAccepted_redirectsAsPending() {
        givenAccount();
        givenStepUp(true);
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        when(startPhoneEnrolmentUseCase.execute(userId, TYPED))
                .thenReturn(new PhoneEnrolmentStarted(Duration.ofMinutes(1)));

        final var response = controller.startPhoneEnrolmentPage(TYPED);

        assertRedirect(response, "pending");
        verify(rateLimiter).checkGeneration(ADDRESS, "phone:" + userId);
    }

    /** A number that is not valid is reported, not sent a code. */
    @Test
    void startPhoneEnrolmentPage_whenTheNumberIsInvalid_redirectsAsInvalidPhone() {
        givenAccount();
        givenStepUp(true);
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        when(startPhoneEnrolmentUseCase.execute(userId, TYPED)).thenThrow(new InvalidPhoneNumberException());

        assertRedirect(controller.startPhoneEnrolmentPage(TYPED), "invalid-phone");
    }

    /** A number of a country SMS messages are not sent to is reported. */
    @Test
    void startPhoneEnrolmentPage_whenTheCountryIsNotAllowed_redirectsAsCountryNotAllowed() {
        givenAccount();
        givenStepUp(true);
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        when(startPhoneEnrolmentUseCase.execute(userId, TYPED)).thenThrow(new SmsCountryNotAllowedException());

        assertRedirect(controller.startPhoneEnrolmentPage(TYPED), "country-not-allowed");
    }

    /** Too many requests are reported before anything is sent. */
    @Test
    void startPhoneEnrolmentPage_whenOverTheLimit_redirectsAsRateLimitedWithoutSending() {
        givenAccount();
        givenStepUp(true);
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        doThrow(new OttRateLimitExceededException(Duration.ofSeconds(RETRY_SECONDS))).when(rateLimiter)
                .checkGeneration(any(), any());

        assertRedirect(controller.startPhoneEnrolmentPage(TYPED), "rate-limited");
        verifyNoInteractions(startPhoneEnrolmentUseCase);
    }

    /**
     * A session that does not satisfy the step-up of an account with a confirmed second factor cannot start replacing
     * the phone: nothing is limited or sent.
     */
    @Test
    void startPhoneEnrolmentPage_whenTheStepUpIsNotSatisfied_redirectsAsStepUpRequiredWithoutSending() {
        givenAccount();
        givenStepUp(false);

        assertRedirect(controller.startPhoneEnrolmentPage(TYPED), "step-up-required");
        verifyNoInteractions(startPhoneEnrolmentUseCase, rateLimiter);
    }

    /** A right code verifies the phone. */
    @Test
    void verifyPhonePage_whenTheCodeIsRight_redirectsAsVerified() {
        givenAccount();
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        when(confirmPhoneUseCase.execute(userId, "alice", CODE)).thenReturn(true);

        assertRedirect(controller.verifyPhonePage(CODE), "verified");
        verify(rateLimiter).checkVerification(ADDRESS, "phone:" + userId);
    }

    /** A wrong code is reported. */
    @Test
    void verifyPhonePage_whenTheCodeIsWrong_redirectsAsInvalidCode() {
        givenAccount();
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        when(confirmPhoneUseCase.execute(userId, "alice", CODE)).thenReturn(false);

        assertRedirect(controller.verifyPhonePage(CODE), "invalid-code");
    }

    /** Too many attempts are reported without checking the code. */
    @Test
    void verifyPhonePage_whenOverTheLimit_redirectsAsRateLimitedWithoutChecking() {
        givenAccount();
        when(request.getRemoteAddr()).thenReturn(ADDRESS);
        doThrow(new OttRateLimitExceededException(Duration.ofSeconds(RETRY_SECONDS))).when(rateLimiter)
                .checkVerification(any(), any());

        assertRedirect(controller.verifyPhonePage(CODE), "rate-limited");
        verifyNoInteractions(confirmPhoneUseCase);
    }

    /** A session that satisfies the step-up removes the phone. */
    @Test
    void removePhonePage_whenTheStepUpIsSatisfied_removesThePhone() {
        givenAccount();
        final var authentication = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(stepUp.isSatisfied(userId, authentication)).thenReturn(true);

        assertRedirect(controller.removePhonePage(), "removed");
        verify(removePhoneUseCase).execute(userId, "alice");
    }

    /** A session that does not satisfy the step-up removes nothing. */
    @Test
    void removePhonePage_whenTheStepUpIsNotSatisfied_redirectsAsStepUpRequired() {
        givenAccount();
        final var authentication = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(stepUp.isSatisfied(userId, authentication)).thenReturn(false);

        assertRedirect(controller.removePhonePage(), "step-up-required");
        verifyNoInteractions(removePhoneUseCase);
    }

    /** The path of the page is the one of the contract. */
    @Test
    void phonePath_whenRead_isTheContractPath() {
        assertEquals("/account/phone", PhonePageController.PHONE_PATH);
    }

    /**
     * Signs the session in and tells whether it satisfies the step-up.
     *
     * @param satisfied whether the step-up is satisfied.
     */
    private void givenStepUp(final boolean satisfied) {
        final var authentication = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(stepUp.isSatisfied(userId, authentication)).thenReturn(satisfied);
    }

    /** Makes the request come from the account. */
    private void givenAccount() {
        when(currentAccountResolver.resolve()).thenReturn(new CurrentAccount(userId, "alice"));
    }

    /**
     * Checks that a response redirects to the page with a status.
     *
     * @param response the response.
     * @param status   the expected status.
     */
    private static void assertRedirect(final ResponseEntity<Void> response, final String status) {
        assertEquals(HttpStatus.SEE_OTHER, response.getStatusCode());
        assertEquals("/account/phone?status=" + status, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }
}
