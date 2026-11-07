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
 * PostgreSQL implementations of the SMS ports: the verified phone numbers and the phone verifications in progress
 * (both over the {@code user_phones} table) and the SMS cost ledger (over the {@code sms_cost_ledger} table).
 */
package com.irurueta.authserver.authorization.infrastructure.persistence.sms;
