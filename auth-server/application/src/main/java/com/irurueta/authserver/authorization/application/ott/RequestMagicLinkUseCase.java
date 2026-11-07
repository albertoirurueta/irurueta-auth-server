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

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Sends a magic link to the verified e-mail address of an enabled account. It is enumeration-safe: for an unknown
 * identifier, a disabled account or an address that is not verified nothing is sent and nothing is reported. The link
 * is not delivered here but through an {@link EmailLinkRequested} event, handled after the transaction commits and off
 * the request thread, so that no remote call runs inside a transaction and the mail server's latency does not show.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class RequestMagicLinkUseCase {

    /** Use case that finds the e-mail address of the account. */
    private final ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Policy of the tokens, which sets the lifetime shown with the link. */
    private final OttPolicy ottPolicy;

    /** Publishes the delivery request. */
    private final ApplicationEventPublisher eventPublisher;

    /**
     * Requests the delivery of a link.
     *
     * @param identifier the name the user signs in with.
     * @param link       the link that opens the confirmation page.
     */
    public void execute(final String identifier, final URI link) {
        resolveOttDestinationUseCase.execute(identifier, OttChannel.EMAIL).ifPresent(destination ->
                eventPublisher.publishEvent(new EmailLinkRequested(destination.address(), link,
                        ottPolicy.ttl(OttKind.LINK))));
    }
}
