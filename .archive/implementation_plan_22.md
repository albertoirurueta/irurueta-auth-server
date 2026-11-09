# Implementation plan: tag regions for the docs Project Setup page

## Task summary

The docs page *Project Setup & Running the Example* (albertoirurueta/docs#343, PR albertoirurueta/docs#379) can only
show code through `include::irurueta-auth-server::example$…[tag=…]`. Several files it describes have no `tag::` regions
or are not collected by the Antora Collector, so the page explains them in prose. This task adds the regions and the
missing Collector scans. No behaviour changes: only comments (XML, YAML, Java) and `docs/antora.yml`.

Choices made on the user's behalf:
- Tag names are `setup-<what>` (lowercase kebab-case, feature first, per the tag-comment convention in `CLAUDE.md`).
- The six module poms are collected by widening their existing scan from `src/**` to `{pom.xml,src/**}` (same `into`
  directory), instead of adding six more scan entries. The CI workflows get one new scan rooted at `~+`.
- `docs.yml` is collected too (the issue says "optionally"): one glob, no extra cost. Only `build.yml` gets a region.
- The issue's "mail relay and seeding properties" region of `auth-server/boot/.../application-dev.yml` is split in two:
  `setup-auth-server-dev-mail` (`spring.mail`) and `setup-auth-server-dev-seed` (the `authserver.clients` redirect URIs
  the dev seeding uses). The file has no other seeding property.
- The demo-user region excludes the `log.warn(...)` that prints the generated password, so the region carries no
  credential value (the password is generated at run time and the file holds none).

Source: GitHub issue #22
Base branch: main
Open clarifications: none

## Acceptance criteria coverage

| # | Criterion | Covered by tasks |
|---|---|---|
| 1 | "Each file above has the tagged regions listed, with `tag::name[]` / `end::name[]` comments in the file's own comment syntax." | Task 1, Task 2, Task 3, Task 4, Task 5, Task 6 |
| 2 | "`docs/antora.yml` collects the module poms and the CI workflow." | Task 7 |
| 3 | "The tag names are listed in the PR description, so the docs follow-up can replace the prose in `project-setup.adoc` with includes." | Task 9 |
| 4 | "`./mvnw verify` stays green." | Task 8 |

## Current code state

- `docs/antora.yml`: Collector `scan` list, one entry per module with `files: 'src/**'` into
  `modules/ROOT/examples/<module path>`; last entry `dir: '~+'`, `files: '{pom.xml,compose.yaml}'`, `into:
  modules/ROOT/examples` (so `example$pom.xml`, `example$compose.yaml`). Module poms and `.github/workflows` are not
  collected.
- Root `pom.xml`: Apache license comment, then `<parent>` `spring-boot-starter-parent` 4.1.2 (lines 21-26),
  `<properties>` with `<java.version>21</java.version>` and `<maven.compiler.release>21</maven.compiler.release>`
  (lines 84-85), and `maven-enforcer-plugin` execution `enforce-build-environment` with `requireJavaVersion
  [21,26)` and `requireMavenVersion [3.9,)` (about lines 436-462). No tags.
- Module poms (starter `<dependency>` blocks, no tags):
  `auth-server/api/web/pom.xml` (webmvc, authorization-server, thymeleaf, resource-server, oauth2-client, validation),
  `auth-server/infrastructure/persistence/pom.xml` (jdbc, flyway, flyway-database-postgresql),
  `auth-server/boot/pom.xml` (validation, actuator, spring-boot-docker-compose, ...),
  `bff/api/web/pom.xml` (webmvc, oauth2-client, validation),
  `bff/infrastructure/session/pom.xml` (session-jdbc, jdbc, flyway, flyway-database-postgresql),
  `resource-server/api/web/pom.xml` (webmvc, resource-server, validation).
- `compose.yaml`: services `postgres` (image `postgres:18`, env incl. a throwaway password carrying
  `# pragma: allowlist secret`, healthcheck) and `mailpit`. Already collected.
- `auth-server/boot/src/main/resources/application-dev.yml`: `spring.docker.compose` (enabled, `file: ../../compose.yaml`,
  `lifecycle-management: start_and_stop`), `spring.mail` (host `localhost`, port `1025`) and `authserver.clients`
  redirect URIs for `bff` and `spa-public`.
- `bff/boot/src/main/resources/application-dev.yml`: only `spring.docker.compose` (same three keys).
- `auth-server/infrastructure/persistence/src/main/java/com/irurueta/authserver/authorization/infrastructure/persistence/dev/DevDataInitializer.java`:
  `createDemoUser()` (about lines 139-154) inserts into `users`, `user_authorities`, `user_passwords` with a generated
  password, then `log.warn(...)` prints it.
- `.github/workflows/build.yml`: workflow `Build and test`, single job `verify` (checkout, JDK 21, Playwright cache,
  `./mvnw -B -ntp clean verify`, Sonar, report upload). `docs.yml` publishes the docs.
- Gates that apply: license-header check (every file keeps its Apache header), Checkstyle/PMD/SpotBugs (Java comments
  only, so unaffected), JaCoCo (unchanged). Never rename or remove an existing tag.

## Implementation steps

### Group 1 (Parallelizable: yes, every task edits a different file)

- [x] Task 1. Tag the root `pom.xml`
  - [x] Task 1.1. Wrap the `<parent>` block (spring-boot-starter-parent) in `<!-- tag::setup-parent[] -->` /
    `<!-- end::setup-parent[] -->`
  - [x] Task 1.2. Wrap the Java version properties (`java.version`, `maven.compiler.release`) in `setup-java-version`
  - [x] Task 1.3. Wrap the `maven-enforcer-plugin` `<plugin>` block in `setup-enforcer`
  - Tags go on their own lines, outside the elements they wrap; the Apache header stays above all regions.
- [x] Task 2. Tag the six module poms: wrap the starter `<dependency>` blocks of each module in one region
  - [x] Task 2.1. `auth-server/api/web/pom.xml`: `setup-auth-server-api-web-starters`
  - [x] Task 2.2. `auth-server/infrastructure/persistence/pom.xml`: `setup-auth-server-persistence-starters`
  - [x] Task 2.3. `auth-server/boot/pom.xml`: `setup-auth-server-boot-starters` (the runtime starters, not the test ones)
  - [x] Task 2.4. `bff/api/web/pom.xml`: `setup-bff-api-web-starters`
  - [x] Task 2.5. `bff/infrastructure/session/pom.xml`: `setup-bff-session-starters`
  - [x] Task 2.6. `resource-server/api/web/pom.xml`: `setup-resource-server-api-web-starters`
- [x] Task 3. Tag `compose.yaml` with `# tag::…[]` / `# end::…[]`: `setup-compose-postgres` around the `postgres` service
  and `setup-compose-mailpit` around the `mailpit` service. Keep `# pragma: allowlist secret` on its line.
- [x] Task 4. Tag the two dev profiles
  - [x] Task 4.1. `auth-server/boot/.../application-dev.yml`: `setup-auth-server-dev-compose` (`spring.docker.compose`),
    `setup-auth-server-dev-mail` (`spring.mail`), `setup-auth-server-dev-seed` (`authserver.clients` redirect URIs).
    `spring` appears once as a key, so each region wraps the nested block with its parent key lines as needed so that
    the included text is valid YAML on its own.
  - [x] Task 4.2. `bff/boot/.../application-dev.yml`: `setup-bff-dev-compose` around the `spring.docker.compose` block
- [x] Task 5. Tag the demo-user seed in `DevDataInitializer.java` _(java-springboot)_
  - [x] Task 5.1. `// tag::setup-demo-user[]` / `// end::setup-demo-user[]` inside `createDemoUser()` around the three
    inserts (user, authority, password hash), ending before `log.warn(...)` so no credential or password variable is
    printed by the region. Javadoc and behaviour are unchanged.
- [x] Task 6. Tag `.github/workflows/build.yml`: `# tag::setup-ci-build-job[]` / `# end::setup-ci-build-job[]` around
  the `verify` job (from `verify:` through its last step)

### Group 2 (Parallelizable: yes, one file; needs the tag paths of Group 1 only for naming)

- [x] Task 7. Collect the new files in `docs/antora.yml`
  - [x] Task 7.1. Change `files: 'src/**'` to `files: '{pom.xml,src/**}'` for the six modules of Task 2
    (`auth-server/api/web`, `auth-server/infrastructure/persistence`, `auth-server/boot`, `bff/api/web`,
    `bff/infrastructure/session`, `resource-server/api/web`); update the comment above the scans accordingly.
  - [x] Task 7.2. Add a scan `dir: '~+'`, `files: '.github/workflows/{build,docs}.yml'`, `into:
    modules/ROOT/examples` so the files land at `example$.github/workflows/build.yml`. If the Collector skips
    dot-directories, switch to the option or glob that includes them and note the finding in the scan's comment.

### Group 3 (Parallelizable: no, verifies the finished groups)

- [x] Task 8. Verify
  - [x] Task 8.1. Build the docs (`cd docs && npm ci && npx antora antora-playbook.yml`) and confirm the module poms,
    `compose.yaml`, `application-dev.yml` files and `build.yml` appear under the collected `examples` tree, and
    that every new tag has a matching `end::` (a `grep` count of `tag::setup-` vs `end::setup-`).
  - [x] Task 8.2. Delegate `./mvnw -B clean verify` to the `iru-gate-runner` agent (it must stay green) and run the
    license-header check (`iru-check-license`) on the touched files; run `iru-check-security` since two YAML files
    containing dev values were edited.
- [x] Task 9. Document the tags
  - [x] Task 9.1. In `CLAUDE.md`, extend the tag-comment convention paragraph with the new collected files (module poms,
    `compose.yaml`, the two workflows) so a new module's pom is scanned.
  - [x] Task 9.2. Keep a table of every tag name added (file, tag) ready for the PR description: setup-parent,
    setup-java-version, setup-enforcer, the six `*-starters` tags, setup-compose-postgres, setup-compose-mailpit,
    setup-auth-server-dev-compose, setup-auth-server-dev-mail, setup-auth-server-dev-seed, setup-bff-dev-compose,
    setup-demo-user, setup-ci-build-job.

  Note (Task 9.2), tags added (file, tag); 17 `tag::setup-` and 17 `end::setup-`:

  | Tag | File |
  |---|---|
  | setup-parent | pom.xml |
  | setup-java-version | pom.xml |
  | setup-enforcer | pom.xml |
  | setup-auth-server-api-web-starters | auth-server/api/web/pom.xml |
  | setup-auth-server-persistence-starters | auth-server/infrastructure/persistence/pom.xml |
  | setup-auth-server-boot-starters | auth-server/boot/pom.xml |
  | setup-bff-api-web-starters | bff/api/web/pom.xml |
  | setup-bff-session-starters | bff/infrastructure/session/pom.xml |
  | setup-resource-server-api-web-starters | resource-server/api/web/pom.xml |
  | setup-compose-postgres | compose.yaml |
  | setup-compose-mailpit | compose.yaml |
  | setup-auth-server-dev-compose | auth-server/boot/src/main/resources/application-dev.yml |
  | setup-auth-server-dev-mail | auth-server/boot/src/main/resources/application-dev.yml |
  | setup-auth-server-dev-seed | auth-server/boot/src/main/resources/application-dev.yml |
  | setup-bff-dev-compose | bff/boot/src/main/resources/application-dev.yml |
  | setup-demo-user | auth-server/infrastructure/persistence/src/main/java/com/irurueta/authserver/authorization/infrastructure/persistence/dev/DevDataInitializer.java |
  | setup-ci-build-job | .github/workflows/build.yml |
