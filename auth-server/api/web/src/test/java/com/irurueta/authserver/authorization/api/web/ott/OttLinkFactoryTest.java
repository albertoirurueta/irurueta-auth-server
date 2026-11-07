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

import java.net.URI;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link OttLinkFactory}. */
class OttLinkFactoryTest {

    /** The link points at the confirmation page of the issuer and carries the token. */
    @Test
    void confirmationLink_whenCalled_pointsAtTheConfirmationPageOfTheIssuer() {
        final var link = new OttLinkFactory("https://auth.example.com").confirmationLink("abc-123");

        assertEquals(URI.create("https://auth.example.com/login/ott/confirm?token=abc-123"), link);
    }

    /** An issuer with a path keeps it. */
    @Test
    void confirmationLink_whenIssuerHasAPath_keepsIt() {
        final var link = new OttLinkFactory("http://localhost:9000/auth").confirmationLink("t");

        assertEquals(URI.create("http://localhost:9000/auth/login/ott/confirm?token=t"), link);
    }
}
