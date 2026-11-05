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

/**
 * Account lifecycle: registration, e-mail verification, password change and reset.
 *
 * <p><strong>{@link com.irurueta.authserver.authorization.domain.account.SignedTokenService}</strong>
 *
 * <p>Issues and verifies short-lived, signed, self-contained tokens (JWTs) that are bound to one <em>purpose</em>.
 * The contract is deliberately independent of the account use cases so that other features can reuse it, for example
 * the client assertions of a later issue:
 * <ul>
 *   <li>{@code issue(subject, purpose, ttl)} returns a compact token whose subject, purpose and expiry are signed;
 *   the expiry is the issue instant plus {@code ttl}.</li>
 *   <li>{@code verify(token, purpose)} returns the subject only when the signature, the issuer, the timestamps and
 *   the purpose all check out; for anything else (expired, tampered, wrong purpose, malformed) it returns an empty
 *   optional and never throws, and it never reveals which check failed.</li>
 *   <li>A token proves a claim but is not single-use: anything that must be consumed once uses an
 *   {@link com.irurueta.authserver.authorization.domain.account.AccountTokenRepository} instead.</li>
 * </ul>
 *
 * <p><strong>{@link com.irurueta.authserver.authorization.domain.account.AccountMailer}</strong>
 *
 * <p>Sends the transactional e-mails of the account lifecycle. The messages are plain text and the implementation
 * chooses the wording and the language, never the platform's default locale. A delivery failure is reported as an
 * {@link com.irurueta.authserver.authorization.domain.account.AccountMailException} (never the mail framework's own
 * type, and never with the address or the token in it), so that the calling use case's transaction rolls back and
 * nothing is left stored for a message that was never delivered. The callers keep their answer independent of
 * whether an address is registered: every registration path sends a message, and the reset-request endpoint answers
 * the same even when its message cannot be delivered. The methods receive the raw token or the link material the
 * message must contain and never a password.
 */
package com.irurueta.authserver.authorization.domain.account;
