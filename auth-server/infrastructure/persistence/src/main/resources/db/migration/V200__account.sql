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

-- tag::account-schema[]
ALTER TABLE users
    ADD COLUMN email          varchar(320),
    ADD COLUMN email_verified boolean      NOT NULL DEFAULT FALSE,
    ADD COLUMN tenant         varchar(100) NOT NULL DEFAULT 'default';

-- Existing rows have no e-mail; the unique index is case-insensitive and ignores the NULLs.
CREATE UNIQUE INDEX uq_users_email ON users (lower(email));

CREATE TABLE account_tokens
(
    id           uuid                     NOT NULL,
    user_id      uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose      varchar(50)              NOT NULL,
    hashed_token varchar(128)             NOT NULL,
    expires_at   timestamp with time zone NOT NULL,
    used_at      timestamp with time zone,
    created_at   timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_account_tokens_hashed_token UNIQUE (hashed_token)
);

CREATE INDEX ix_account_tokens_expires_at ON account_tokens (expires_at);
-- end::account-schema[]
