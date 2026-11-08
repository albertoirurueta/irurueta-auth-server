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

-- tag::federated-schema[]
-- One row per identity of an external provider linked to a user. The provider's stable subject, never its e-mail
-- address, finds the user, so (provider, subject) is unique: one external identity belongs to one account.
CREATE TABLE federated_identities
(
    id            uuid                     NOT NULL,
    user_id       uuid                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider      varchar(32)              NOT NULL,
    subject       varchar(255)             NOT NULL,
    email         varchar(320),
    linked_at     timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at timestamp with time zone,
    PRIMARY KEY (id),
    CONSTRAINT uq_federated_identities_provider_subject UNIQUE (provider, subject),
    CONSTRAINT ck_federated_identities_provider CHECK (provider IN ('google', 'microsoft', 'apple', 'github'))
);

CREATE INDEX ix_federated_identities_user_id ON federated_identities (user_id);
-- end::federated-schema[]
