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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.application.sms.SendSmsOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.sms.SmsMessages;
import com.irurueta.authserver.authorization.application.sms.SmsRefusedException;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Sends a one-time code to a user, by e-mail or SMS.
 *
 * <p>The request is enumeration-safe: for an unknown identifier, a disabled account or an account without a verified
 * address for the channel nothing is stored or sent, yet the same result is returned and a code is still generated
 * and hashed, so the work done is alike. A refused SMS (country, budget) or a delivery failure is logged without the
 * identifier, the address or the code and is not reported to the caller.
 *
 * <p>A new code replaces the previous one of the same binding and user (the repository saves one active code per
 * binding and username). Magic links are not handled here: they use the framework's token service.
 */
@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class RequestOneTimeCodeUseCase {

    /** Use case that finds where the code is delivered. */
    private final ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Generator of codes. */
    private final OneTimeCodeGenerator oneTimeCodeGenerator;

    /** Hasher of codes. */
    private final OneTimeCodeHasher oneTimeCodeHasher;

    /** Port that stores the codes. */
    private final OneTimeCodeRepository oneTimeCodeRepository;

    /** Port that delivers the codes by e-mail. */
    private final OttDelivery ottDelivery;

    /** Use case that sends the codes by SMS. */
    private final SendSmsOneTimeCodeUseCase sendSmsOneTimeCodeUseCase;

    /** Policy of the codes. */
    private final OttPolicy ottPolicy;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Requests a code.
     *
     * @param identifier the name the user signs in with, as typed.
     * @param channel    the channel to deliver the code through.
     * @param purpose    what the code is for.
     * @param bindingId  identifier of the sign-in attempt the code is bound to (for example the session id).
     * @return the same result for every identifier.
     */
    public OneTimeCodeRequestResult execute(
            final String identifier, final OttChannel channel, final OttPurpose purpose, final String bindingId) {
        final var ttl = ottPolicy.ttl(OttKind.CODE);
        final var result = new OneTimeCodeRequestResult(true, ttl);
        final var code = oneTimeCodeGenerator.generate(ottPolicy.codeLength());
        final var hash = oneTimeCodeHasher.hash(code);
        final var destination = resolveOttDestinationUseCase.execute(identifier, channel).orElse(null);
        if (destination == null) {
            return result;
        }
        final var now = clock.instant();
        oneTimeCodeRepository.save(new OneTimeCode(UUID.randomUUID(), identifier, channel, purpose, hash, bindingId,
                0, now.plus(ttl), now));
        deliver(destination, code, ttl);
        return result;
    }

    /**
     * Delivers a code, swallowing any refusal or failure.
     *
     * @param destination where to deliver it.
     * @param code        the clear-text code.
     * @param ttl         how long it is valid.
     */
    private void deliver(final OttDestination destination, final String code, final Duration ttl) {
        try {
            if (destination.channel() == OttChannel.EMAIL) {
                ottDelivery.deliverCode(OttChannel.EMAIL, destination.address(), code, ttl);
            } else {
                sendSmsOneTimeCodeUseCase.execute(new PhoneNumber(destination.address()),
                        SmsMessages.verificationCode(code, ttl));
            }
        } catch (final OttDeliveryException | SmsDeliveryException | SmsRefusedException e) {
            log.warn("A one-time code was not delivered by {}: {}", destination.channel(),
                    e.getClass().getSimpleName());
        }
    }
}
