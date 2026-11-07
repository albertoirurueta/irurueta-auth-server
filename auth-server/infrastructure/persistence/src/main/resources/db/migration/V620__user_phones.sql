-- Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--         http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- tag::sms-phones-schema[]
-- One row per user. phone_e164 and verified_at hold the verified number (unique, so one number belongs to one user);
-- the pending_* columns hold a verification in progress, with the code hashed. A pending number does not reserve it.
CREATE TABLE user_phones
(
    user_id             uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    phone_e164          varchar(16),
    verified_at         timestamp with time zone,
    pending_phone_e164  varchar(16),
    pending_code_hash   varchar(128),
    pending_attempts    integer      NOT NULL DEFAULT 0,
    pending_expires_at  timestamp with time zone,
    PRIMARY KEY (user_id),
    CONSTRAINT uq_user_phones_phone_e164 UNIQUE (phone_e164),
    CONSTRAINT ck_user_phones_verified CHECK ((phone_e164 IS NULL) = (verified_at IS NULL)),
    CONSTRAINT ck_user_phones_pending CHECK ((pending_phone_e164 IS NULL) = (pending_code_hash IS NULL)
        AND (pending_phone_e164 IS NULL) = (pending_expires_at IS NULL)),
    CONSTRAINT ck_user_phones_phone_shape CHECK (phone_e164 IS NULL OR phone_e164 ~ '^\+[1-9][0-9]{6,14}$'),
    CONSTRAINT ck_user_phones_pending_shape CHECK (pending_phone_e164 IS NULL
        OR pending_phone_e164 ~ '^\+[1-9][0-9]{6,14}$')
);

CREATE INDEX ix_user_phones_pending_expires_at ON user_phones (pending_expires_at);
-- end::sms-phones-schema[]
