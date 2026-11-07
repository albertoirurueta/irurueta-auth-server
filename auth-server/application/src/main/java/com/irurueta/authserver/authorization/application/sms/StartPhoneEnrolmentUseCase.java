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

package com.irurueta.authserver.authorization.application.sms;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNormalizer;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Starts the enrolment of a phone: normalises the number and sends it a verification code.
 *
 * <p>What may be visible and what may not: an invalid number ({@link InvalidPhoneNumberException}) and a country that
 * is not served ({@link SmsCountryNotAllowedException}) depend on the input alone and reveal nothing about any
 * account, so they fail visibly. Everything that depends on the state of other accounts or of the system is
 * indistinguishable from success: a number already verified by another user (no message is sent, no state is
 * stored, but the same work is done), an exhausted SMS budget and a provider failure (the message is sent after the
 * transaction commits, off the request thread, by the delivery of {@link SmsRequested}, which records a failure without
 * the number or the code). Otherwise an attacker could learn which numbers belong to accounts.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class StartPhoneEnrolmentUseCase {

    /** Port that normalises the typed number. */
    private final PhoneNormalizer phoneNormalizer;

    /** Port that finds the country of a number. */
    private final PhoneCountryResolver phoneCountryResolver;

    /** Port that reads the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verification. */
    private final PhoneVerificationRepository phoneVerificationRepository;

    /** Generator of the verification code. */
    private final OneTimeCodeGenerator oneTimeCodeGenerator;

    /** Hasher of the verification code. */
    private final OneTimeCodeHasher oneTimeCodeHasher;

    /** Use case that records the cost of the message and requests it. */
    private final SendSmsOneTimeCodeUseCase sendSmsOneTimeCodeUseCase;

    /** SMS settings. */
    private final SmsProperties smsProperties;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Starts the enrolment.
     *
     * @param userId identifier of the user.
     * @param phone  the number as typed, with or without country code.
     * @return the validity of the code; the same whether or not a message was sent.
     * @throws InvalidPhoneNumberException   if the text is not a valid number.
     * @throws SmsCountryNotAllowedException if the country of the number is unknown or not served.
     */
    public PhoneEnrolmentStarted execute(final UUID userId, final String phone) {
        final var number = phoneNormalizer.normalize(phone, smsProperties.defaultRegion())
                .orElseThrow(InvalidPhoneNumberException::new);
        phoneCountryResolver.countryOf(number)
                .filter(country -> smsProperties.allowedCountries().contains(country))
                .orElseThrow(SmsCountryNotAllowedException::new);
        final var result = new PhoneEnrolmentStarted(smsProperties.verificationCodeTtl());
        final var code = oneTimeCodeGenerator.generate(smsProperties.verificationCodeLength());
        final var hash = oneTimeCodeHasher.hash(code);
        final var takenByAnother = userPhoneRepository.findByPhone(number)
                .map(UserPhone::userId)
                .filter(owner -> !owner.equals(userId))
                .isPresent();
        if (takenByAnother) {
            return result;
        }
        phoneVerificationRepository.save(new PhoneVerification(userId, number, hash, 0,
                clock.instant().plus(smsProperties.verificationCodeTtl())));
        send(number, code);
        return result;
    }

    /**
     * Requests the code, swallowing a refusal so that it cannot be told apart from success.
     *
     * @param number the destination.
     * @param code   the clear-text code.
     */
    private void send(final PhoneNumber number, final String code) {
        try {
            sendSmsOneTimeCodeUseCase.execute(number, SmsMessages.verificationCode(code,
                    smsProperties.verificationCodeTtl()));
        } catch (final SmsRefusedException ignored) {
            // refused by the budget policy: answered like a sent code, so nothing is revealed
        }
    }
}
