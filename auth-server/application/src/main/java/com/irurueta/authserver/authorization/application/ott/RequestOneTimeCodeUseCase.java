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
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Sends a one-time code to a user, by e-mail or SMS.
 *
 * <p>The request is enumeration-safe: for an unknown identifier, a disabled account or an account without a verified
 * address for the channel nothing is stored or sent, yet the same result is returned and a code is still generated
 * and hashed, so the work done is alike. The code is never delivered inside this transaction: an e-mail is requested
 * through an {@link EmailCodeRequested} event and an SMS through {@link SendSmsOneTimeCodeUseCase}, which records its
 * cost and publishes an {@code SmsRequested} event; both are handled after the transaction commits and off the request
 * thread, so no remote call holds a database connection and the latency of the mail server or the SMS gateway cannot
 * tell an existing account from an unknown one. A refused SMS (country, budget) is not reported to the caller.
 *
 * <p>A new code replaces the previous one of the same binding and user (the repository saves one active code per
 * binding and username). Magic links are not handled here: they use the framework's token service.
 */
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

    /** Publishes the request of an e-mail delivery. */
    private final ApplicationEventPublisher eventPublisher;

    /** Use case that records the cost of an SMS and requests its delivery. */
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
        requestDelivery(destination, code, ttl);
        return result;
    }

    /**
     * Requests the delivery of a code, swallowing an SMS refusal so that it cannot be told apart from success.
     *
     * @param destination where to deliver it.
     * @param code        the clear-text code.
     * @param ttl         how long it is valid.
     */
    private void requestDelivery(final OttDestination destination, final String code, final Duration ttl) {
        if (destination.channel() == OttChannel.EMAIL) {
            eventPublisher.publishEvent(new EmailCodeRequested(destination.address(), code, ttl));
            return;
        }
        try {
            sendSmsOneTimeCodeUseCase.execute(new PhoneNumber(destination.address()),
                    SmsMessages.verificationCode(code, ttl));
        } catch (final SmsRefusedException ignored) {
            // refused by the country or budget policy: answered like a sent code, so nothing is revealed
        }
    }
}
