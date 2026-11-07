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

-- WebAuthn (passkeys): Spring Security's official PostgreSQL schema, kept column for column because the framework's
-- JdbcPublicKeyCredentialUserEntityRepository and JdbcUserCredentialRepository run their own SQL against it. It
-- already holds the label, creation and last use of each credential, so nothing of ours is added to the tables. Two
-- tightenings that the framework's SQL does not notice: a user entity name (the account's username) is unique, so the
-- lookup of the passkeys of an account has one answer, and the creation and last use are instants
-- (timestamp with time zone, like every other instant of this schema), not local date-times.
-- tag::passkeys-schema[]
CREATE TABLE user_entities
(
    id           varchar(1000) NOT NULL,
    name         varchar(100)  NOT NULL,
    display_name varchar(200),
    PRIMARY KEY (id),
    CONSTRAINT uq_user_entities_name UNIQUE (name)
);

CREATE TABLE user_credentials
(
    credential_id                varchar(1000) NOT NULL,
    user_entity_user_id          varchar(1000) NOT NULL,
    public_key                   bytea         NOT NULL,
    signature_count              bigint,
    uv_initialized               boolean,
    backup_eligible              boolean       NOT NULL,
    authenticator_transports     varchar(1000),
    public_key_credential_type   varchar(100),
    backup_state                 boolean       NOT NULL,
    attestation_object           bytea,
    attestation_client_data_json bytea,
    created                      timestamp with time zone,
    last_used                    timestamp with time zone,
    label                        varchar(1000) NOT NULL,
    PRIMARY KEY (credential_id)
);

CREATE INDEX ix_user_credentials_user_entity_user_id ON user_credentials (user_entity_user_id);
-- end::passkeys-schema[]
