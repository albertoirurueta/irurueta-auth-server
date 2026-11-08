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
package com.irurueta.authserver.authorization.application.social;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;

/**
 * The account a sign-in with an external provider resolved to.
 *
 * @param account  the local account, whose identifier becomes the {@code sub} of the issued tokens.
 * @param identity the link between the account and the provider's identity, as stored.
 * @param outcome  how the account was found.
 */
public record FederatedLogin(UserAccount account, FederatedIdentity identity, FederatedLoginOutcome outcome) {
}
