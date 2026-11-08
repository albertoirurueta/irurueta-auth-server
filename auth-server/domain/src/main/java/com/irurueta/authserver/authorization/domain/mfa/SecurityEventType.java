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
package com.irurueta.authserver.authorization.domain.mfa;

/**
 * Kinds of authentication events that are recorded for audit.
 */
public enum SecurityEventType {

    /** A user authenticated with the primary factor. */
    LOGIN_SUCCESS,

    /** An authentication with the primary factor failed. */
    LOGIN_FAILURE,

    /** A second factor was verified. */
    SECOND_FACTOR_SUCCESS,

    /** A second factor was rejected. */
    SECOND_FACTOR_FAILURE,

    /** The second factor of a user was locked after too many failed attempts. */
    SECOND_FACTOR_LOCKED,

    /** A user trusted a device. */
    TRUSTED_DEVICE_ADDED,

    /** A trusted device skipped the second factor. */
    TRUSTED_DEVICE_USED,

    /** A trusted device was revoked. */
    TRUSTED_DEVICE_REVOKED,

    /** A recovery code was spent in place of a second factor. */
    RECOVERY_CODE_USED,

    /** A user removed a second factor, which also revokes every trusted device of the user. */
    SECOND_FACTOR_REMOVED,

    /** An identity of an external provider was linked to an account, or an account was created from one. */
    IDENTITY_LINKED,

    /** An identity of an external provider was unlinked from an account. */
    IDENTITY_UNLINKED,

    /** A client certificate was bound to an account. */
    CERTIFICATE_BOUND,

    /** A client certificate was unbound from an account. */
    CERTIFICATE_UNBOUND
}
