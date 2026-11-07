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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsInbox;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import com.irurueta.authserver.testsupport.MailpitClient;
import com.irurueta.authserver.testsupport.MailpitTestConfiguration;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Shared set-up of the one-time token integration tests: the application with a real database and a Mailpit
 * container that receives its e-mail (read back through the Mailpit HTTP API), the logging SMS sender whose messages
 * the tests read through the {@link SmsInbox} port (both delivered after the request, off its thread, so the tests
 * wait for them), and the steps of the browser flow: ask for a token, post a code,
 * open and confirm a magic link. Every user, password and token is generated at runtime. The per-client limits are
 * raised so that the many requests of one test class, which all come from the same address, are not limited; the
 * per-identifier limits stay at their defaults and every test uses a user of its own.
 */
@Import(MailpitTestConfiguration.class)
@TestPropertySource(properties = {
        "authserver.ott.rate-limit.generation-per-client=10000",
        "authserver.ott.rate-limit.verification-per-client=10000"})
abstract class AbstractOttFlow extends AbstractMfaFlow {

    /** Path of the endpoint that generates a token. */
    static final String GENERATE = "/ott/generate";

    /** Path of the page and the endpoint that takes a code or the token of a link. */
    static final String LOGIN_OTT = "/login/ott";

    /** Path of the page a magic link opens. */
    static final String CONFIRM = "/login/ott/confirm";

    /** Path of the endpoint that takes the code of a second factor. */
    static final String SECOND_FACTOR_OTT = "/login/second-factor/ott";

    /** Name of the field of the token and the code at sign-in. */
    static final String TOKEN_FIELD = "token";

    /** {@code amr} of a user who signed in with an e-mail code or link only. */
    static final List<String> EMAIL_AMR = List.of("otp");

    /** {@code amr} of a user who signed in with an SMS code only. */
    static final List<String> SMS_AMR = List.of("sms");

    /** Phone number of the generated users, in a country the default settings allow. */
    private static final String SPANISH_PREFIX = "+346";

    /** Number of digits after the prefix of a generated phone number. */
    private static final int PHONE_DIGITS = 8;

    /** Number of values of a decimal digit. */
    private static final int DECIMAL = 10;

    /** Longest wait for an SMS, which is sent after the request that asked for it. */
    private static final Duration SMS_WAIT = Duration.ofSeconds(15);

    /** Pause between two looks at the SMS inbox, in milliseconds. */
    private static final long SMS_POLL_MILLIS = 50L;

    /** Matches the digits of the code of an SMS. */
    private static final Pattern SMS_CODE = Pattern.compile("code is ([0-9]+)");

    /** Reads the e-mail the application sent. */
    @Autowired
    private MailpitClient mailpit;

    /** Reads the SMS the logging sender recorded. */
    @Autowired
    private SmsInbox smsInbox;

    /** Port that stores the verified phones. */
    @Autowired
    private UserPhoneRepository userPhones;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository accounts;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder encoder;

    /** Pins the locale of the texts the tests read. */
    @BeforeEach
    void pinTheLocale() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    /** Restores the locale. */
    @AfterEach
    void restoreTheLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    /**
     * Returns the client of the Mailpit HTTP API.
     *
     * @return the client.
     */
    protected MailpitClient mailpit() {
        return mailpit;
    }

    /**
     * Returns the SMS the logging sender recorded.
     *
     * @return the inbox.
     */
    protected SmsInbox smsInbox() {
        return smsInbox;
    }

    /**
     * Creates a user whose e-mail address is verified and who has a verified phone in a country SMS may be sent to.
     *
     * @return the user and its phone number.
     */
    protected UserWithPhone createUserWithPhone() {
        return createUserWithPhone(SPANISH_PREFIX + digits());
    }

    /**
     * Creates a user whose e-mail address is verified and who has a verified phone.
     *
     * @param e164 phone number of the user, in E.164 form.
     * @return the user and its phone number.
     */
    protected UserWithPhone createUserWithPhone(final String e164) {
        return attachPhone(getFixtures().createUser(), e164);
    }

    /**
     * Creates a disabled user whose e-mail address is verified and who has a verified phone.
     *
     * @return the user and its phone number.
     */
    protected UserWithPhone createDisabledUserWithPhone() {
        return attachPhone(createUserWithStatus(false, true), SPANISH_PREFIX + digits());
    }

    /**
     * Gives an existing user a verified phone in a country SMS may be sent to.
     *
     * @param user the user.
     * @return the user and its phone number.
     */
    protected UserWithPhone withPhone(final AuthServerFixtures.TestUser user) {
        return attachPhone(user, SPANISH_PREFIX + digits());
    }

    /**
     * Gives a user a verified phone.
     *
     * @param user the user.
     * @param e164 phone number of the user, in E.164 form.
     * @return the user and its phone number.
     */
    private UserWithPhone attachPhone(final AuthServerFixtures.TestUser user, final String e164) {
        final var phone = new PhoneNumber(e164);
        userPhones.save(new UserPhone(accounts.findByUsername(user.username()).orElseThrow().id(), phone,
                Instant.now()));
        return new UserWithPhone(user, phone);
    }

    /**
     * Creates a user with the given account status.
     *
     * @param enabled       whether the account is enabled.
     * @param emailVerified whether the e-mail address is verified.
     * @return the user.
     */
    protected AuthServerFixtures.TestUser createUserWithStatus(final boolean enabled, final boolean emailVerified) {
        final var username = "user-" + UUID.randomUUID();
        final var credential = AuthServerFixtures.randomValue();
        final var email = username + "@example.com";
        accounts.save(new UserAccount(UUID.randomUUID(), username, encoder.encode(credential), enabled,
                List.of("ROLE_USER"), email, emailVerified, AuthServerFixtures.TENANT));
        return new AuthServerFixtures.TestUser(username, credential, email);
    }

    /**
     * Generates random digits for a phone number.
     *
     * @return {@value #PHONE_DIGITS} digits.
     */
    protected static String digits() {
        final var random = new SecureRandom();
        final var builder = new StringBuilder();
        for (var i = 0; i < PHONE_DIGITS; i++) {
            builder.append(random.nextInt(DECIMAL));
        }
        return builder.toString();
    }

    /**
     * Posts the form that asks for a token and checks it is answered with the redirect to the "check your inbox" page.
     *
     * @param session  the browser session.
     * @param username identifier typed by the user (ignored for a second factor, which uses the signed-in user).
     * @param channel  {@code email} or {@code sms}.
     * @param kind     {@code code} or {@code link}.
     * @param purpose  {@code login} or {@code second-factor}.
     * @throws Exception if the request cannot be performed.
     */
    protected void requestToken(final MockHttpSession session, final String username, final String channel,
            final String kind, final String purpose) throws Exception {
        getMockMvc().perform(generate(session, username, channel, kind, purpose)).andExpect(status().isFound())
                .andExpect(redirectedUrl(LOGIN_OTT));
    }

    /**
     * Builds the post that asks for a token.
     *
     * @param session  the browser session.
     * @param username identifier typed by the user.
     * @param channel  {@code email} or {@code sms}.
     * @param kind     {@code code} or {@code link}.
     * @param purpose  {@code login} or {@code second-factor}.
     * @return the request.
     */
    protected static MockHttpServletRequestBuilder generate(final MockHttpSession session, final String username,
            final String channel, final String kind, final String purpose) {
        return post(GENERATE).session(session).with(csrf()).with(AbstractMfaFlow::sendsTheSessionCookie)
                .param("username", username).param("channel", channel).param("kind", kind)
                .param("purpose", purpose);
    }

    /**
     * Posts a code or the token of a link to the sign-in endpoint.
     *
     * @param session the browser session.
     * @param token   the code or the token.
     * @return the answer of the filter.
     * @throws Exception if the request cannot be performed.
     */
    protected MvcResult postToken(final MockHttpSession session, final String token) throws Exception {
        return getMockMvc().perform(post(LOGIN_OTT).session(session).with(csrf())
                .with(AbstractMfaFlow::sendsTheSessionCookie).param(TOKEN_FIELD, token)).andReturn();
    }

    /**
     * Posts the code of a second factor.
     *
     * @param session the browser session.
     * @param code    the code.
     * @return the answer of the filter.
     * @throws Exception if the request cannot be performed.
     */
    protected MvcResult postSecondFactorCode(final MockHttpSession session, final String code) throws Exception {
        return getMockMvc().perform(post(SECOND_FACTOR_OTT).session(session).with(csrf())
                .with(AbstractMfaFlow::sendsTheSessionCookie).param("code", code)).andReturn();
    }

    /**
     * Reads the code of the last SMS sent to a number, waiting for the first one to arrive.
     *
     * @param phone the number.
     * @return the digits of the code.
     * @throws InterruptedException if the wait is interrupted.
     */
    protected String lastSmsCode(final PhoneNumber phone) throws InterruptedException {
        awaitSmsCount(phone, 1L);
        final var texts = smsInbox.entries().stream().filter(entry -> entry.to().equals(phone))
                .map(SmsInboxEntry::text).toList();
        assertFalse(texts.isEmpty(), "No SMS was sent to the number");
        final var matcher = SMS_CODE.matcher(texts.getLast());
        assertTrue(matcher.find(), "The SMS carries no code");
        return matcher.group(1);
    }

    /**
     * Waits until at least a number of SMS were sent to a number.
     *
     * @param phone    the number.
     * @param expected the number of messages to wait for.
     * @return the number of messages sent, at least {@code expected}.
     * @throws InterruptedException if the wait is interrupted.
     */
    protected long awaitSmsCount(final PhoneNumber phone, final long expected) throws InterruptedException {
        final var deadline = System.nanoTime() + SMS_WAIT.toNanos();
        var count = smsCount(phone);
        while (count < expected && System.nanoTime() < deadline) {
            Thread.sleep(SMS_POLL_MILLIS);
            count = smsCount(phone);
        }
        assertTrue(count >= expected, "Expected " + expected + " SMS for the number but found " + count);
        return count;
    }

    /**
     * Counts the SMS sent to a number so far.
     *
     * @param phone the number.
     * @return the number of messages.
     */
    protected long smsCount(final PhoneNumber phone) {
        return smsInbox.entries().stream().filter(entry -> entry.to().equals(phone)).count();
    }

    /**
     * Builds a code of the same length that is not the given one.
     *
     * @param code the right code.
     * @return a wrong code.
     */
    protected static String wrongCodeLike(final String code) {
        final var zeros = "0".repeat(code.length());
        return zeros.equals(code) ? "1".repeat(code.length()) : zeros;
    }

    /**
     * Makes a request come from another client address.
     *
     * @param request the request.
     * @param address the address.
     * @return the same request.
     */
    protected static MockHttpServletRequest from(final MockHttpServletRequest request, final String address) {
        request.setRemoteAddr(address);
        return request;
    }

    /**
     * A generated user with a verified phone.
     *
     * @param user  the user.
     * @param phone the verified phone number.
     */
    record UserWithPhone(AuthServerFixtures.TestUser user, PhoneNumber phone) {
    }
}
