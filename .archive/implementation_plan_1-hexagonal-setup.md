# Implementation plan: hexagonal restructure, conventions and build gates (PR #10 follow-up)

## Task summary

Bring the repository in line with the rewritten `CLAUDE.md` (read it first, in full: it is the specification for
every task below), on the PR #10 branch:

1. Restructure every application into a hexagonal Maven sub-reactor (`domain`, `application`,
   `infrastructure/<adapter>`, `api/<adapter>`, `boot`), enforced by per-module enforcer `bannedDependencies` and an
   ArchUnit `HexagonalArchitectureTest` per application.
2. Refactor the existing code and tests to the new rules: JUnit assertions (no AssertJ), Mockito instead of
   hand-written doubles, `method_whenCondition_result` test names, one test class per production class, `*Test` only
   for context-free unit tests (anything with a Spring context or slice becomes `*IT`), `final var` and type
   witnesses, records, full Javadoc (tests too), named constants, modern collection accessors, method references,
   `switch`, no redundant `this`, Spring `StringUtils`/`CollectionUtils`, Lombok (`@RequiredArgsConstructor`,
   `@Slf4j`), LF line endings, pinned locales.
3. Turn the report-only analysis into failing build gates: Checkstyle (tests included), PMD + CPD, SpotBugs, JaCoCo
   80% line / 70% branch on an aggregated `coverage` module.
4. Add SonarCloud analysis to the *Build and test* workflow (no deployment), and refresh README and Antora docs.

Source: PR #10 review follow-up (GitHub issue #1); the user asked for this explicitly. No existing issue (#1–#8)
covers the repository setup.
Base branch: main (work continues on `feature/1-walking-skeleton-security-chains-persistence`, PR #10)

Reference implementation for build configuration and style: `/Users/airurueta/repositories/napptilus/napp-sesame-api-proxy`
(read-only — never modify it). Copy and adapt from it: root `pom.xml` build section (enforcer, Surefire/Failsafe
split, JaCoCo merge + check, Checkstyle/PMD/CPD/SpotBugs executions, Sonar properties and plugin, reporting),
`checkstyle.xml`, `spotbugs-exclude.xml`, `coverage/pom.xml`, `.gitattributes`, `boot/src/test/.../HexagonalArchitectureTest.java`,
the per-module enforcer `bannedDependencies` blocks (`domain/pom.xml`, `application/pom.xml`, `api/*/pom.xml`,
`infrastructure/*/pom.xml`) and the Sonar step of `.github/workflows/ci.yml`. Keep this repository's plugin versions
where they are newer, and its group/package names.

Choices made (challenge in review):
- **Not contract-first.** napp-sesame-api-proxy generates controllers from `apis/` OpenAPI specs; this repository keeps
  issue #1's springdoc-annotations + `openapi/` drift-test approach, because albertoirurueta/docs#159 fixes that rule
  for all eight issues.
- **Sonar coordinates** `sonar.organization=albertoirurueta`, `sonar.projectKey=albertoirurueta_irurueta-auth-server`,
  `sonar.host.url=https://sonarcloud.io` (SonarCloud's GitHub-import defaults). The workflow step is skipped when the
  `SONAR_TOKEN` secret is absent, so CI stays green before the project exists.
- **Docs tag names do not change**, but every include path does (`example$auth-server/src/...` →
  `example$auth-server/api/web/src/...`); the guide pages are not written yet, so list the new paths per tag in the
  final report.
- Use `git mv` for every moved file so history follows it.

Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | derived: every application is split into hexagonal modules and the layering is enforced by enforcer `bannedDependencies` and an ArchUnit test | Task 2, Task 3, Task 4, Task 5, Task 6, Task 7 |
| 2 | derived: all code and tests follow the `CLAUDE.md` Testing and Java style rules (JUnit assertions, Mockito, naming, `*Test`/`*IT`, Lombok, Javadoc, …) | Task 3, Task 4, Task 5, Task 6, Task 8 |
| 3 | derived: Checkstyle, PMD/CPD, SpotBugs and the JaCoCo 80%/70% aggregate gate fail `./mvnw -B clean verify`, and it is green | Task 1, Task 9, Task 12 |
| 4 | derived: the *Build and test* workflow runs the tests and SonarCloud analysis, with no deployment | Task 10 |
| 5 | derived: README and Antora docs describe the new layout, gates and Sonar; Collector scans resolve the new module paths | Task 11 |

## Current code state

- Branch `feature/1-walking-skeleton-security-chains-persistence` (PR #10). Root reactor modules: `test-support`,
  `auth-server`, `bff`, `resource-server`, `service-client`, `e2e-tests`; each application is one flat Spring Boot
  module. Quality plugins are report-only (`<reporting>`), the root `checkstyle.xml` is an older ruleset with tabs.
- `auth-server` (`com.irurueta.authserver.authorization`): `AuthServerApplication`, `SecurityConfig` (protocol chain
  `@Order(1)`, login chain `@Order(2)` applying `LoginChainCustomizer`s before the catch-all), `OpenApiConfig`,
  `DevDataInitializer` (`@Profile("dev")`, uses `JdbcClient` directly for users + `RegisteredClientRepository`),
  `clients/JdbcAuthorizationServerConfiguration` (SAS JDBC beans), `keys/TemporaryJwkConfiguration`,
  `login/{LoginChainCustomizer,LoginController,LoginMethodFragment}`, `password/{JdbcUserDetailsService,PasswordConfiguration}`,
  14 feature `package-info.java` placeholders, resources `application.yml`, `application-dev.yml`
  (`docker.compose.file: ../compose.yaml`), `db/migration/V100__…sql`, `V101__users.sql`, `templates/login.html`;
  tests listed by `git ls-files 'auth-server/src/test/**'` (several `*Test` classes use AssertJ and `@WebMvcTest`
  slices with a hand-written `@TestConfiguration` and anonymous `LoginMethodFragment`/`LoginChainCustomizer`).
- `bff`: `security/SecurityConfig` (oauth2Login, PKCE), `user/UserController` (`GET /bff/user`), tests incl.
  `BffApplicationTest` (Spring context named `*Test`).
- `resource-server`: `security/SecurityConfig` (JWT, `audiences: bff`), `orders/{Order,OrdersController}` (`GET /orders`,
  hard-coded demo data), tests incl. `ResourceServerApplicationTest`.
- `service-client`: placeholder `ServiceClientApplication` + `ServiceClientApplicationTest`.
- `e2e-tests/SignInSmokeIT` launches `auth-server/target/*.jar` and `bff/target/*.jar` (paths change with the split)
  and parses the dev credential log lines.
- Docs tags in use: `security-chains`, `login-form`, `sas-schema`, `users-schema`, `jdbc-services`,
  `password-load-user`, `bff-security`, `bff-user`, `resource-server-security`, `resource-server-orders`.
- `docs/antora.yml` `ext.collector` scans one `dir` per flat module.

## Implementation steps

### Group 1 — Root build and repository files (Parallelizable: no — Tasks 2–8 build on the root pom)

- [x] Task 1. Root build configuration _(java-springboot)_
  - Files: `.gitattributes`, `pom.xml`, `checkstyle.xml`, `spotbugs-exclude.xml`, `coverage/pom.xml`. No CRLF files existed. Reactor compiles; `verify` with gates skipped succeeds. Gates (Checkstyle etc.) intentionally fail on unrefactored modules until Group 4 Task 9. No tests added (build-only).
  - [x] Task 1.1. `.gitattributes` with `* text=auto eol=lf` (copy from the reference); renormalize if any file has CRLF.
  - [x] Task 1.2. Root `pom.xml`: version properties for Lombok-free plugins, `archunit.version`,
    `sonar-maven-plugin.version`, the reference's `checkstyle.config.location`, Sonar properties (see Task summary,
    `sonar.coverage.jacoco.xmlReportPaths` → `coverage/target/site/jacoco-aggregate/jacoco.xml`). `dependencyManagement`
    for every internal artifact (`<app>-domain`, …) and ArchUnit. Lombok as a `provided` dependency for all modules and
    in `maven-compiler-plugin` `annotationProcessorPaths` (plus `spring-boot-configuration-processor`).
  - [x] Task 1.3. Build plugins as in the reference: enforcer (`[21,26)`, Maven 3.9+), Surefire `**/*Test.java` /
    Failsafe `**/*IT.java`, JaCoCo (prepare-agent, prepare-agent-integration, report, merge, check 0.80/0.70 per
    module is NOT wanted — keep the check only in `coverage`; per-module report stays), Checkstyle `check` at
    `validate` with tests included, PMD `check` + `cpd-check` at `verify`, SpotBugs `check` (Medium/Max,
    `spotbugs-exclude.xml`), Sonar plugin; `<reporting>` keeps javadoc/jxr/surefire-report/checkstyle/pmd/spotbugs.
  - [x] Task 1.4. Replace `checkstyle.xml` with the reference's ruleset (spaces, `MethodName` suppression for
    `.*(Test|IT)\.java$`, `FinalParameters`, `MagicNumber`, Javadoc checks on tests); add the single
    `HideUtilityClassConstructor` suppression for `*Application.java`. Add `spotbugs-exclude.xml` (start from the
    reference; keep only entries that apply, each with a comment).
  - [x] Task 1.5. Root `<modules>`: `test-support`, `auth-server`, `bff`, `resource-server`, `service-client`,
    `e2e-tests`, `coverage` (new). `coverage/pom.xml` from the reference: depends on every module with code, runs
    `jacoco:merge` over `**/target/jacoco*.exec`, `report-aggregate`, and the 80%/70% `check`.

### Group 2 — auth-server split (Parallelizable: no — modules depend on each other in order)

- [x] Task 2. `auth-server` aggregator and module poms _(java-springboot)_
  - Done: `auth-server/pom.xml` (`auth-server-parent`), `infrastructure/pom.xml`, `api/pom.xml` aggregators; leaf poms for domain, application, infrastructure/{persistence,keys}, api/web, boot with enforcer `bannedDependencies` (all pass); root `dependencyManagement`, `coverage/pom.xml` and `e2e-tests/pom.xml` jar path updated.
  - `auth-server/pom.xml` becomes packaging `pom`, artifactId `auth-server-parent`, modules `domain`, `application`,
    `infrastructure` (aggregator with `persistence`, `keys`), `api` (aggregator with `web`), `boot`. Each leaf pom
    carries the enforcer `bannedDependencies` for its layer (CLAUDE.md table). Only `boot` applies
    `spring-boot-maven-plugin` (repackage).
- [x] Task 3. auth-server code into layers _(java-springboot)_
  - [x] Task 3.1. `domain` (`…authorization.domain.password`): `UserAccount` record (`UUID id`, `String username`,
    `String encodedPassword`, `boolean enabled`, `List<String> authorities`; compact-constructor validation with
    `IllegalArgumentException`, `List.copyOf`) and port `UserAccountRepository` (`Optional<UserAccount> findByUsername(String)`).
    Move the 14 feature `package-info.java` placeholders to `api/web` (`…api.web.<feature>`), except `password`
    which now has code in every layer.
  - [x] Task 3.2. `application` (`…application.password`): `FindUserAccountUseCase` (plain class; constructor rejects a
    null port with `IllegalArgumentException`; `Optional<UserAccount> execute(String username)`).
  - [x] Task 3.3. `infrastructure/persistence` (`…infrastructure.persistence`): `password/JdbcUserAccountRepository`
    (the two queries now in `JdbcUserDetailsService`, keep tag `password-load-user` around the lookup method),
    `clients/JdbcAuthorizationServerConfiguration` (tag `jdbc-services`), Flyway migrations moved to this module's
    `src/main/resources/db/migration` (tags `sas-schema`, `users-schema`), JDBC/Flyway/PostgreSQL deps.
  - [x] Task 3.4. `infrastructure/keys` (`…infrastructure.keys`): `TemporaryJwkConfiguration`.
  - [x] Task 3.5. `api/web` (`…api.web`): `SecurityConfig` (tag `security-chains`), `OpenApiConfig`,
    `login/{LoginChainCustomizer,LoginMethodFragment,LoginController}`, `templates/login.html` (tag `login-form`),
    `password/UserAccountUserDetailsService` (Spring Security `UserDetailsService` adapter over
    `FindUserAccountUseCase`, maps `UserAccount` → `User`; replaces `JdbcUserDetailsService`), `password/PasswordConfiguration`
    (only the `PasswordEncoder` bean, still `// TEMPORARY: replaced in #2`).
  - [x] Task 3.6. `boot` (root package `…authorization`): `AuthServerApplication`, `BeanConfiguration` composition root
    (`@Bean FindUserAccountUseCase`), `DevDataInitializer` (`@Slf4j`, `@RequiredArgsConstructor`, credential log lines
    unchanged so `SignInSmokeIT` still parses them), `application.yml` (+ `spring.messages.fallback-to-system-locale:
    false`, `spring.web.locale: en`), `application-dev.yml` (`file: ../../compose.yaml`).
- [x] Task 4. auth-server tests to the new rules _(java-springboot)_
  - Done: 12 unit test classes (incl. extra `JdbcUserAccountRepositoryTest`, `BeanConfigurationTest`), 8 `*IT`, `HexagonalArchitectureTest` (9 rules). `./mvnw -B -pl auth-server/boot -am verify -Dcheckstyle.skip` is green (test-support's own Checkstyle findings are pre-existing and out of scope); Checkstyle clean on every auth-server module; PMD/CPD/SpotBugs clean. Unit-only line coverage 100% except `SecurityConfig` (0%, covered by ITs only: framework wiring), `BeanConfiguration` (covered by its unit test) and `TemporaryJwkConfiguration` (83%, unreachable catch).
  - Unit tests (`*Test`, Mockito + JUnit, no Spring context) beside each class in its module: `UserAccountTest`,
    `FindUserAccountUseCaseTest`, `UserAccountUserDetailsServiceTest`, `LoginControllerTest`, `LoginMethodFragmentTest`,
    `OpenApiConfigTest`, `PasswordConfigurationTest`, `TemporaryJwkConfigurationTest`,
    `JdbcAuthorizationServerConfigurationTest`, `DevDataInitializerTest`.
  - Integration tests (`*IT`): `JdbcUserAccountRepositoryIT` (persistence, Testcontainers + Flyway), the former
    `SecurityConfigTest` slice becomes `SecurityConfigIT` in `boot` (or `api/web`) with `@MockitoBean`s / Mockito
    mocks instead of the anonymous customizer/fragment beans; `SecurityIT`, `AuthorizationCodePkceIT`,
    `OpenApiDriftIT` (LF-only write/compare), `DevDataInitializerIT`, `JdbcServicesIT`, `AuthServerApplicationIT` in `boot`.
  - `HexagonalArchitectureTest` (ArchUnit, a `*Test`) in `boot`: domain depends on nothing outside the JDK/Lombok,
    application only on domain, api never on infrastructure, infrastructure adapters not on each other or on api.
  - Every test: `method_whenCondition_result` names, full Javadoc, `final var`, constants instead of magic numbers,
    public → private ordering, one test class per production class.

### Group 3 — bff, resource-server, service-client splits (Parallelizable: yes — separate sub-reactors)

- [x] Task 5. `bff` _(java-springboot)_
  - Modules `domain` (`…bff.domain.user.SessionUser(String subject)` record; validated, blank subject →
    `IllegalArgumentException`), no `application` (no use case until #3, per CLAUDE.md), `api/web`
    (`security/SecurityConfig` tag `bff-security`, `user/UserController` tag `bff-user` returning a
    `SessionUserResponse` record DTO, springdoc `@Operation`/`@Tag` on the endpoint), `boot`
    (`BffApplication`, `application.yml`). No `infrastructure` until #3. Tests per Task 4's rules;
    `BffApplicationTest` → `BffApplicationIT` (merge with the existing one), `HexagonalArchitectureTest`.
  - Done: modules bff-domain, bff-api-web, bff-boot (no application/infrastructure); unit tests 100% line on SessionUser, UserController, SessionUserResponse (SecurityConfig covered by SecurityConfigIT only, framework wiring); BffApplicationIT/SecurityConfigIT/UserControllerIT/HexagonalArchitectureTest green; enforcer, Checkstyle, PMD, CPD, SpotBugs clean.
- [x] Task 6. `resource-server` _(java-springboot)_
  - `domain` (`…resourceserver.domain.orders.Order` record moved from the web layer, port `OrderRepository`
    `List<Order> findAll()`), `application` (`ListOrdersUseCase`), `infrastructure/demo` (`InMemoryOrderRepository`
    returning the two demo orders), `api/web` (`security/SecurityConfig` tag `resource-server-security`,
    `orders/OrdersController` tag `resource-server-orders` mapping to an `OrderResponse` DTO, springdoc annotations),
    `boot` (`ResourceServerApplication`, `BeanConfiguration`, `application.yml` keeping `audiences`). Tests per Task 4;
    `ResourceServerApplicationTest` → `*IT`; `HexagonalArchitectureTest`.
  - Done: modules resource-server-{domain,application,infrastructure-demo,api-web,boot}; unit tests 100% line on every class except SecurityConfig (IT only); ResourceServerApplicationIT/OrdersControllerIT/HexagonalArchitectureTest green; enforcer, Checkstyle, PMD, CPD, SpotBugs clean.
- [x] Task 7. `service-client` _(java-springboot)_
  - Becomes `service-client/boot` only (aggregator + boot), per CLAUDE.md; `ServiceClientApplicationTest` → `*IT` if it
    starts a context; `package-info` notes #8 adds the other layers.
  - Done: service-client-boot only; ServiceClientApplicationIT green; no HexagonalArchitectureTest until #8 gives it layers.

### Group 4 — Shared modules, gates green, CI and docs (Parallelizable: no — Task 9 needs Tasks 1–8, Task 11 needs the final paths)

- [x] Task 8. `test-support` and `e2e-tests` _(java-springboot)_
  - Done: test-support/PostgresTestConfigurationIT and e2e-tests SignInSmokeIT restyled (Javadoc, naming, JUnit assertions, final var); ManagedApp extracted to its own class; e2e-tests depends on auth-server-boot and bff-boot (test scope, all transitives excluded); jar paths point at */boot/target.
  - Apply the style rules (Javadoc, naming, Lombok, `final var`). `SignInSmokeIT`: jar paths → `auth-server/boot/target`
    and `bff/boot/target`; `e2e-tests` depends on the two `boot` artifacts so the reactor orders it after them.
- [x] Task 9. Make every gate pass _(java-springboot)_
  - Done: `./mvnw -B -ntp clean verify` green. Only 3 Checkstyle findings were left (bff-boot x2 line length, resource-server-boot magic number), fixed in code. Aggregate coverage 98.84% line / 100% branch; no suppressions added.
  - Run `./mvnw -B clean verify` via `iru-gate-runner`; fix every Checkstyle/PMD/CPD/SpotBugs finding in code (no blanket
    suppressions; a justified per-line suppression only with a comment), and add tests until the `coverage` gate
    passes (80% line / 70% branch). Never lower a threshold.
- [x] Task 10. CI workflow _(untagged)_
  - Done: .github/workflows/build.yml: job verify (JDK 21, fetch-depth 0, Playwright browser cache), SonarCloud step guarded by env.SONAR_TOKEN, report upload; no deploy.
  - `.github/workflows/build.yml`: keep `verify` (JDK 21, Docker on ubuntu-latest, Playwright browsers install step
    if needed), add `fetch-depth: 0`, then a SonarCloud step `./mvnw -B -ntp sonar:sonar` with `SONAR_TOKEN` and
    `GITHUB_TOKEN`, guarded by `if: env.SONAR_TOKEN != ''`; upload test/coverage reports. No deploy job.
- [x] Task 11. README and Antora docs _(untagged)_
  - Done: README.md (layout, commands, gates, Sonar and CI badges), docs/antora.yml (one scan per module), architecture/installation/reference/data-model pages; scratch include resolved and was deleted.
  - `README.md`: layout, commands, build gates, Sonar badge (SonarCloud quality gate + coverage) and CI badge.
  - `docs/antora.yml` collector: one `scan` per module directory (`auth-server/domain`, …, `test-support`,
    `e2e-tests`), each `files: 'src/**'`, `into: modules/ROOT/examples/<module-path>`; root `pom.xml`, `compose.yaml`.
    Build the docs with a scratch include of `example$auth-server/api/web/src/main/java/…/SecurityConfig.java[tag=security-chains]`,
    confirm it resolves, delete the scratch page.
  - Update `architecture.adoc`, `installation.adoc`, `reference.adoc`, `data-model.adoc` for the new module paths,
    the hexagonal rules, build gates and Sonar (or run `/iru-update-docs`).
- [x] Task 12. Final verification _(untagged)_
  - Done: verify green incl. e2e (SignInSmokeIT ran, 1 test); security scan flagged 17 vs 16 baseline (see report).
  - `./mvnw -B clean verify` green (all gates, all `*IT`, e2e). `/iru-check-security`: nothing new. Report the new
    include path for each of the 10 docs tags.
