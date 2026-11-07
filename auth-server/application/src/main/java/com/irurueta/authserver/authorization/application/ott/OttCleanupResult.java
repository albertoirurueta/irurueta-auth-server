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

/**
 * Number of rows removed by a cleanup run.
 *
 * @param codes              expired one-time codes.
 * @param phoneVerifications expired pending phone verifications.
 * @param ledgerEntries      SMS cost ledger rows older than the retention.
 * @param linkTokens         expired magic-link tokens.
 */
public record OttCleanupResult(int codes, int phoneVerifications, int ledgerEntries, int linkTokens) {
}
