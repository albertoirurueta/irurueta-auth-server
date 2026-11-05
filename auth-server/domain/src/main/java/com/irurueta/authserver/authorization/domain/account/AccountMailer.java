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

package com.irurueta.authserver.authorization.domain.account;

/**
 * Port that sends the e-mails of the account lifecycle. See the package documentation for its contract.
 */
public interface AccountMailer {

    /**
     * Asks the owner of an address to confirm it.
     *
     * @param email address the message is sent to.
     * @param token signed verification token to include in the message.
     */
    void sendEmailVerification(String email, String token);

    /**
     * Tells the owner of an address that someone tried to register it again.
     *
     * @param email address the message is sent to.
     */
    void sendAlreadyRegistered(String email);

    /**
     * Sends the link that allows choosing a new password.
     *
     * @param email address the message is sent to.
     * @param token single-use reset token to include in the message.
     */
    void sendPasswordReset(String email, String token);

    /**
     * Tells the owner of an address that a reset was requested but no account uses that address.
     *
     * @param email address the message is sent to.
     */
    void sendNoAccountFound(String email);
}
