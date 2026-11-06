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

-- tag::mfa-schema-trusted-devices[]
CREATE TABLE trusted_devices
(
    id           uuid                     NOT NULL,
    user_id      uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    hashed_token varchar(128)             NOT NULL,
    user_agent   varchar(255),
    expires_at   timestamp with time zone NOT NULL,
    created_at   timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uq_trusted_devices_hashed_token UNIQUE (hashed_token)
);

CREATE INDEX ix_trusted_devices_user_id ON trusted_devices (user_id);
CREATE INDEX ix_trusted_devices_expires_at ON trusted_devices (expires_at);
-- end::mfa-schema-trusted-devices[]
