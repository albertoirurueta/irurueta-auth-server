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

package com.irurueta.authserver.authorization.api.web.passkeys;

import java.time.Instant;

/**
 * What the passkeys page shows of a passkey. It is a view model of the page, never a domain object or a DTO of the
 * REST contract.
 *
 * @param label      name that identifies the passkey.
 * @param createdAt  when it was registered.
 * @param lastUsedAt when it last signed in; {@code null} when it never did.
 * @param backedUp   whether the credential is synchronised between devices.
 */
public record PasskeyView(String label, Instant createdAt, Instant lastUsedAt, boolean backedUp) {
}
