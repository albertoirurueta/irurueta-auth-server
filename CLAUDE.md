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

## Package layout of `auth-server`

Everything lives under `com.irurueta.authserver.authorization`. The root package holds only `AuthServerApplication`,
`SecurityConfig` (protocol chain `@Order(1)` and login/UI chain `@Order(2)`), `OpenApiConfig`, the dev-only
`DevDataInitializer` and the temporary pieces. One sub-package per feature, each with a `package-info.java` saying
which issue fills it: `password`, `keys`, `tokens`, `clients`, `login`, `mfa`, `totp`, `passkeys`, `ott`, `social`,
`x509`, `implicit`, `account`, `admin`.

## Extension points: adding a login method without editing shared files

- `login.LoginChainCustomizer` (a `Customizer<HttpSecurity>`): every bean of this type is applied, in `@Order`, to the
  login/UI chain by `SecurityConfig`. A new method declares one in its own `@Configuration` to enable its
  `HttpSecurity` features (for example `http.oneTimeTokenLogin(...)`), so `SecurityConfig` is never edited.
- `login.LoginMethodFragment`: every bean of this type contributes a Thymeleaf fragment (`templateName()`,
  `fragmentName()`, `order()`) that `LoginController` passes to `templates/login.html`, which renders them below the
  password form.

A later issue therefore adds a login method by creating its own package (for example `ott`) with a `@Configuration`,
its controller/services, a template under `templates/<method>.html`, a `LoginChainCustomizer` bean and a
`LoginMethodFragment` bean, plus its own Flyway migration in its range. No existing file needs to change.

## Tag-comment convention

Code included by the docs guide is wrapped in `tag::<feature>-<what>[]` / `end::<feature>-<what>[]` markers
(lowercase kebab-case, feature first, for example `security-chains`, `login-form`, `sas-schema`, `bff-user`). The
comment syntax follows the file type: `// tag::x[]` in Java, `-- tag::x[]` in SQL, `# tag::x[]` in YAML/properties and
`<!-- tag::x[] -->` in HTML/XML. Antora includes them with
`include::irurueta-auth-server::example$<module>/src/...[tag=x]`; the Antora Collector copies each module's `src/**`
(plus the root `pom.xml` and `compose.yaml`) into the `example$` family, so paths start with the module name.

## Flyway ranges

Migrations live in `auth-server/src/main/resources/db/migration` (`classpath:db/migration`). The skeleton uses
`V100`-`V199` (`V100` Spring Authorization Server schema, `V101` users). Each later issue takes its own hundred-block
so parallel branches never collide: issue #2 `V200`-`V299`, #3 `V300`-`V399`, and so on (issue number x 100).

## Testing

- `test-support` is a small module (compile scope on the consumers' test classpath, `<scope>test</scope>` in their
  poms) holding `PostgresTestConfiguration` (a `postgres:18` Testcontainers container exposed through
  `@ServiceConnection`) and the `@PostgresIT` meta-annotation: `@SpringBootTest` wired to that container, with a
  `webEnvironment()` attribute for `RANDOM_PORT` tests. Name integration tests `*IT` (Failsafe, `verify` phase).
- `e2e-tests` drives the packaged `auth-server` and `bff` jars through headless Chromium with Playwright for Java.
  Playwright was chosen over Selenium because it manages its own browser binaries, auto-waits for elements (less
  flaky) and needs no driver setup. It depends on `test-support` only and must stay last in the reactor.
- `openapi/auth-server.json` is the committed OpenAPI contract; `OpenApiDriftIT` fails when `/v3/api-docs` differs.
  Regenerate with `./mvnw -pl auth-server verify -Dopenapi.update=true` and commit the result.
