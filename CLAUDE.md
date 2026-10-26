# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An **example** OAuth 2.1 / OpenID Connect authorization server built from scratch with Spring Boot 4.1 and Spring
Security 7.1 (Spring Authorization Server), plus the applications that use it. It backs the step-by-step guide
*Building an Authorization Server from Scratch* in the docs site (repository `albertoirurueta/docs`, under
`modules/ROOT/pages/backend/springboot/authorization-server-from-scratch/`), which includes code from this repository
with tagged regions. It is never deployed: CI only builds and tests it.

## Commands

Requires JDK 21+ (the build enforces it) and Docker for Testcontainers.

```bash
./mvnw verify                          # unit (*Test) + integration (*IT) tests and JaCoCo reports
./mvnw -pl auth-server test -Dtest=AuthServerApplicationTest   # one test class in one module
./mvnw verify site                     # adds Checkstyle/PMD/SpotBugs/JXR reports (report-only)
./mvnw -pl auth-server spring-boot:run # run one application (ports: auth-server 9000, bff 8080, resource-server 8081)
cd docs && npm ci && npx antora antora-playbook.yml            # build this repository's Antora docs
```

## Layout

A plain Maven reactor (not the hexagonal layout of `iru-setup-java-springboot`), one Spring Boot application per
module, all versions declared in the root `pom.xml`:

- `auth-server` (`com.irurueta.authserver.authorization`): the authorization server and its login/consent/MFA/account pages.
- `bff` (`com.irurueta.authserver.bff`): Backend-for-Frontend for a browser SPA.
- `resource-server` (`com.irurueta.authserver.resourceserver`): JWT-protected API.
- `service-client` (`com.irurueta.authserver.serviceclient`): client credentials / service-to-service client.
- `docs/`: Antora component `irurueta-auth-server`, aggregated by the docs site.

## Conventions

- Every source file starts with the Apache 2.0 header used in the existing files.
- Each authentication method lives in its own package with its own `@Configuration`, so features can be developed in
  parallel without editing shared files.
- Code shown in the docs guide is marked with AsciiDoc tag comments (`// tag::<feature>-<what>[]` …
  `// end::<feature>-<what>[]`). Never rename or remove a tag without updating the docs repository.
- Never commit secrets, keys or certificates: generate dev keys at first start and test keys inside the tests.
