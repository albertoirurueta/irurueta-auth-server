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

-- tag::totp-schema[]
CREATE TABLE totp_credentials
(
    user_id           uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    encrypted_secret  bytea                    NOT NULL,
    confirmed         boolean                  NOT NULL DEFAULT FALSE,
    last_used_step    bigint                   NOT NULL DEFAULT -1,
    created_at        timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);

CREATE TABLE recovery_codes
(
    id          uuid                     NOT NULL,
    user_id     uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    hashed_code varchar(128)             NOT NULL,
    used_at     timestamp with time zone,
    created_at  timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE INDEX ix_recovery_codes_user_id ON recovery_codes (user_id);
-- end::totp-schema[]
