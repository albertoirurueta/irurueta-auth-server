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
package com.irurueta.authserver.authorization.infrastructure.github;

import com.irurueta.authserver.authorization.infrastructure.github.v1.generated.model.Email;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Maps the e-mail addresses GitHub lists onto the one address the domain wants: the address GitHub marks as both
 * primary and verified. A verified address that is not the primary one, or a primary one that is not verified, does
 * not count.
 */
@Component
public class GitHubEmailMapper {

    /**
     * Picks the verified primary address.
     *
     * @param emails the addresses GitHub answered, possibly {@code null} for an empty body.
     * @return the address, or an empty optional when none is both primary and verified.
     */
    public Optional<String> verifiedPrimary(final List<Email> emails) {
        if (emails == null) {
            return Optional.empty();
        }
        return emails.stream()
                .filter(Objects::nonNull)
                .filter(email -> Boolean.TRUE.equals(email.getPrimary()) && Boolean.TRUE.equals(email.getVerified()))
                .map(Email::getEmail)
                .filter(StringUtils::hasText)
                .findFirst();
    }
}
