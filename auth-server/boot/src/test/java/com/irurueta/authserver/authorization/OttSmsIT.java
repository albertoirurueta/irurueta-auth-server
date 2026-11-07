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
package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Checks the numeric code sent by SMS through the logging sender (read back from its {@code SmsInbox}), as a primary
 * sign-in and as a second factor, and the enrolment of the phone on the account page: the number is normalised, the
 * code of the verification SMS confirms it, and a user with a verified phone is then asked for a second factor.
 */
class OttSmsIT extends AbstractOttFlow {

    /** {@code amr} of a user who presented a password, an SMS code and so more than one factor. */
    private static final List<String> MFA_AMR = List.of("pwd", "sms", "mfa");

    /** {@code amr} of a user who signed in with an SMS code and then a code of the authenticator app. */
    private static final List<String> SMS_MFA_AMR = List.of("sms", "otp", "mfa");

    /** Path of the phone page. */
    private static final String PHONE_PAGE = "/account/phone";

    /** Port that stores the verified phones. */
    @Autowired
    private UserPhoneRepository phones;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /**
     * Verifies that a user with a verified phone who asks for a code by SMS and posts it signs in without a password,
     * and, because a verified phone is a confirmed second factor that makes MFA required, is then asked for a second
     * factor. Neither one-time token channel is offered or delivered as that second factor: not SMS, which signed the
     * user in, and not e-mail, because the user has another confirmed second factor (a mailbox, which also resets the
     * password, never stands in for it). The authenticator app of the user completes the sign-in and the tokens carry
     * {@code amr} {@code sms}, {@code otp} and {@code mfa}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCodeFromSmsIsPosted_signsInAndIsAskedForASecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var owner = withPhone(enrolled.user());
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = plainAuthorizeUri(client, verifier);
        getMockMvc().perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());

        requestToken(session, owner.user().username(), "sms", "code", "login");
        final var sessionId = session.getId();
        assertAccepted(postToken(session, lastSmsCode(owner.phone())));
        assertNotEquals(sessionId, session.getId(), "The session id must change when the user signs in");
        expectSecondFactorPage(authorizeUri, session);
        final var page = secondFactorPage(session);
        assertFalse(page.contains("E-mail me a code"), "E-mail is not offered next to another second factor");
        assertFalse(page.contains("Send me a code by SMS"), "The channel that signed the user in is not offered");
        requestToken(session, owner.user().username(), "email", "code", "second-factor");
        requestToken(session, owner.user().username(), "sms", "code", "second-factor");
        assertEquals(0, mailpit().countMessagesTo(owner.user().email()), "No e-mail second factor is delivered");
        assertEquals(1L, smsCount(owner.phone()), "No SMS second factor is delivered after an SMS sign-in");
        assertAccepted(postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false));
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(SMS_MFA_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
    }

    /**
     * Verifies that a user with a verified phone, who must then present a second factor, completes it with a code sent
     * by SMS after the password, and that the tokens say password, SMS and multi-factor.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenCodeFromSmsIsPosted_issuesTokensThatCarryMfa() throws Exception {
        final var owner = createUserWithPhone();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(owner.user(), client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertTrue(secondFactorPage(session).contains("Send me a code by SMS"));

        requestToken(session, owner.user().username(), "sms", "code", "second-factor");
        final var sessionId = session.getId();
        assertAccepted(postSecondFactorCode(session, lastSmsCode(owner.phone())));
        assertNotEquals(sessionId, session.getId(), "The session id must change with the second factor");
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(MFA_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
    }

    /**
     * Verifies that a wrong SMS code is refused and that the right one still signs the user in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenSmsCodeIsWrong_redirectsBackWithAnError() throws Exception {
        final var owner = createUserWithPhone();
        final var session = new MockHttpSession();
        requestToken(session, owner.user().username(), "sms", "code", "login");
        final var code = lastSmsCode(owner.phone());

        final var wrong = postToken(session, wrongCodeLike(code));

        assertTrue(wrong.getResponse().getRedirectedUrl().endsWith("/login/ott?error"));
        assertAccepted(postToken(session, code));
    }

    /**
     * Verifies the enrolment of a phone on the account page: a number typed in the international format with spaces
     * is normalised, the verification SMS carries the code, the code confirms the phone, and the account then has the
     * verified phone.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void phoneEnrolment_whenCodeFromSmsIsConfirmed_storesTheVerifiedPhone() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        getFixtures().signIn(user, session);
        final var digits = digits();
        final var typed = "+34 6" + digits.substring(0, 2) + " " + digits.substring(2, 5) + " " + digits.substring(5);
        final var phone = new PhoneNumber("+346" + digits);

        getMockMvc().perform(form(PHONE_PAGE, session, "phone", typed))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=pending"));
        assertEquals(1L, awaitSmsCount(phone, 1L));
        getMockMvc().perform(form(PHONE_PAGE + "/verify", session, "code", lastSmsCode(phone)))
                .andExpect(status().isSeeOther())
                .andExpect(redirectedUrl("/account/phone?status=verified"));

        final var id = userAccounts.findByUsername(user.username()).orElseThrow().id();
        assertEquals(phone, phones.findByUserId(id).orElseThrow().phone());
    }

    /**
     * Builds the post a browser makes when it submits a form of the phone page.
     *
     * @param path    path the form posts to.
     * @param session the browser session.
     * @param name    name of the only field.
     * @param value   value of the field.
     * @return the request.
     */
    private static MockHttpServletRequestBuilder form(final String path, final MockHttpSession session,
            final String name, final String value) {
        return post(path).session(session).with(csrf()).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(name, value);
    }
}
