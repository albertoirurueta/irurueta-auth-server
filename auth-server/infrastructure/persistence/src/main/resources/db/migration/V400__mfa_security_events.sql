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

-- tag::mfa-schema-events[]
ALTER TABLE users
    ADD COLUMN mfa_required boolean NOT NULL DEFAULT FALSE;

-- Audit trail. The user is kept as a nullable reference so events of failed logins for unknown names can be stored
-- and so the trail outlives a deleted account.
CREATE TABLE security_events
(
    id          uuid                     NOT NULL,
    type        varchar(50)              NOT NULL,
    user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    username    varchar(100),
    detail      varchar(500),
    occurred_at timestamp with time zone NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX ix_security_events_user_occurred_at ON security_events (user_id, occurred_at);

CREATE TABLE second_factor_attempts
(
    user_id      uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    failed_count integer                  NOT NULL DEFAULT 0,
    locked_until timestamp with time zone,
    PRIMARY KEY (user_id)
);
-- end::mfa-schema-events[]
