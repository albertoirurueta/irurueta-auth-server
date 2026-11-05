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

-- tag::tokens-reuse-detection[]
-- Hashes of the refresh tokens that were rotated out of an authorization. Presenting one of them again means the
-- token was stolen or replayed, so the authorization is revoked.
CREATE TABLE consumed_refresh_tokens
(
    token_hash       varchar(64)              NOT NULL,
    authorization_id varchar(100)             NOT NULL REFERENCES oauth2_authorization (id) ON DELETE CASCADE,
    consumed_at      timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_hash)
);

CREATE INDEX ix_consumed_refresh_tokens_authorization ON consumed_refresh_tokens (authorization_id);
-- end::tokens-reuse-detection[]
