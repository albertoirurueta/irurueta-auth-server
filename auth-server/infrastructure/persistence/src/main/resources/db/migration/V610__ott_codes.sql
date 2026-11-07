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

-- tag::ott-codes-schema[]
CREATE TABLE ott_codes
(
    id         uuid                     NOT NULL,
    username   varchar(100)             NOT NULL,
    channel    varchar(16)              NOT NULL,
    purpose    varchar(32)              NOT NULL,
    code_hash  varchar(128)             NOT NULL,
    binding_id varchar(128)             NOT NULL,
    attempts   integer                  NOT NULL DEFAULT 0,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_ott_codes_channel CHECK (channel IN ('EMAIL', 'SMS')),
    CONSTRAINT ck_ott_codes_purpose CHECK (purpose IN ('LOGIN', 'SECOND_FACTOR')),
    CONSTRAINT ck_ott_codes_attempts CHECK (attempts >= 0)
);

CREATE INDEX ix_ott_codes_binding_username ON ott_codes (binding_id, username);
CREATE INDEX ix_ott_codes_expires_at ON ott_codes (expires_at);
-- end::ott-codes-schema[]
