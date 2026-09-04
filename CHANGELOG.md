# Changelog

All notable changes to `nautilus-rkm` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0](https://github.com/KrakenNet/nautilus/compare/v0.2.5...v0.3.0) (2026-09-04)


### Features

* a credential names the agent it may speak for (WAVE B1) ([fb6eaa6](https://github.com/KrakenNet/nautilus/commit/fb6eaa6e0d1c5b4591dafe27bd502d75a569a511))
* a dead dependency is visible over HTTP, and readiness says what it means (WAVE 14) ([b46dace](https://github.com/KrakenNet/nautilus/commit/b46dace909c0b002067b0865faae14d4329dde17))
* an instance's build answer comes from the artifact, not from argv (WAVE 14) ([d49d388](https://github.com/KrakenNet/nautilus/commit/d49d388a680a6026df0191414f3c17378aa9c40b))
* record engine input facts in the audit entry ([1b65c56](https://github.com/KrakenNet/nautilus/commit/1b65c562feb78b9af98650f42f78ff8c316845c5))
* **rkm:** add evidence-driven conflict resolution stage ([1f5594a](https://github.com/KrakenNet/nautilus/commit/1f5594ae9aed54cfc8415cc8b4895e02d169ad5c))
* **rkm:** add evidence-driven conflict resolution stage ([2c5b502](https://github.com/KrakenNet/nautilus/commit/2c5b502ad32742345cd7e3b3f7e9599752c2f265)), closes [#129](https://github.com/KrakenNet/nautilus/issues/129)
* SIGHUP reloads the subset it can prove safe, and refuses the rest by name (WAVE 12) ([2dea1ea](https://github.com/KrakenNet/nautilus/commit/2dea1ea86ed28d613584b8620c87e1c20ecde799))
* the exposure ledger follows the caller across a key rotation (WAVE 13) ([f5b8969](https://github.com/KrakenNet/nautilus/commit/f5b896932cceffaa1e56a566e800f6f33d351b0c))
* the first five minutes end somewhere worth being (WAVE C2) ([c73d6ea](https://github.com/KrakenNet/nautilus/commit/c73d6ea154241b8695ec65c5de3bdc8d7965b77c))
* the package, the deployment and the MCP surface tell the truth (WAVE C3) ([5947258](https://github.com/KrakenNet/nautilus/commit/5947258f9cc1a8f641b36617b307a5b4a7124699))


### Bug Fixes

* --log-level debug now says something Nautilus knows (WAVE 12) ([579ac7e](https://github.com/KrakenNet/nautilus/commit/579ac7e3b46c9ca74e4af4d20f1dce2e751e9710))
* 1.0 readiness — 97 waves of audit-driven fixes ([9198130](https://github.com/KrakenNet/nautilus/commit/9198130265ce5c453b19f7411bba098d63ff40cd))
* a forged agent_id can no longer land on another caller's ledger (WAVE 13) ([7f42d7a](https://github.com/KrakenNet/nautilus/commit/7f42d7a757b2a671bc666b9e5c492ed30f7fba64))
* a name resolves to one distribution, or to an error (WAVE E10) ([fe92cc5](https://github.com/KrakenNet/nautilus/commit/fe92cc59a35a58189a9c7d66ec9125d0ccee05fe))
* a permanent condition answered with a transient status (WAVE E21) ([ba71b90](https://github.com/KrakenNet/nautilus/commit/ba71b90b25e66613d833f15cbc067aed1a98477e))
* a response is bounded in bytes, and hashing does not copy it (WAVE E9) ([6ace2c0](https://github.com/KrakenNet/nautilus/commit/6ace2c05b8832ff95ddb1bcdea3dd7fd7996a820))
* a rule can write a scope-constraint operator literally (UPSTREAM L) ([767fdbc](https://github.com/KrakenNet/nautilus/commit/767fdbc5cb3e28907ef82c96d04aea5f4bb10aaf))
* a running broker can say which build it is, and the audit log says what it costs (WAVE 10) ([fcc0745](https://github.com/KrakenNet/nautilus/commit/fcc0745ffc29f9055bdda2841c40894a01c81eaf))
* a running instance says which build it is, and the version stops rotting (WAVE 12) ([7defa00](https://github.com/KrakenNet/nautilus/commit/7defa0082fb54f8b0b68297b80866d0c835bb79f))
* a session belongs to somebody, and a refusal says which kind it is (WAVE E13) ([f83cafc](https://github.com/KrakenNet/nautilus/commit/f83cafc22e4b1bc31c679b7603ce9de395f1a359))
* a test run no longer appends to the repository's audit log (UPSTREAM J) ([b56dbbd](https://github.com/KrakenNet/nautilus/commit/b56dbbda55821e2984e44a7fcfeeedfb5b764940))
* adapter lifecycle events have producers, and quarantine clears (UPSTREAM I) ([a0057bf](https://github.com/KrakenNet/nautilus/commit/a0057bf6de642f630fdcffbf4d352bacf928fac7))
* adapters no longer silently alter or discard a scope constraint ([4ad1829](https://github.com/KrakenNet/nautilus/commit/4ad1829e16448444d86ddaa8a68ffb185b8b4c61))
* adapters return what the scope actually says, and say when they truncate (WAVE 5) ([209f0b3](https://github.com/KrakenNet/nautilus/commit/209f0b3f4faa7e3c58ff68aa47763ce814e60f8f))
* an expired scope grant denies the source instead of widening access ([1b3e45f](https://github.com/KrakenNet/nautilus/commit/1b3e45fc440f1c105865996a295474ba4dc16e59))
* an unmapped forwarded subject was a root credential (WAVE E18) ([1c73598](https://github.com/KrakenNet/nautilus/commit/1c73598b1ee8242d76eb3184b6e2b7ed64d33428))
* authenticate the RKM queue and rule-governance endpoints ([081c7d3](https://github.com/KrakenNet/nautilus/commit/081c7d3b9a9a8422952892d600237303a371a33b))
* both documented host reload routes now reach the broker (WAVE 13) ([f4267de](https://github.com/KrakenNet/nautilus/commit/f4267de356bed38a063557fc3da422e90c2ac862))
* bound the queue, and say which policy answered (WAVE E8) ([fe1aee6](https://github.com/KrakenNet/nautilus/commit/fe1aee6be1b90949c7d98bae66639b7a358231d4))
* close the re-audit's eight-item gate, and make two replicas a real deployment (WAVE 7) ([db3ed34](https://github.com/KrakenNet/nautilus/commit/db3ed34596e462a8d75d816947bdf9991046c689))
* close the two live security defects the header audit found (WAVE 7) ([046c705](https://github.com/KrakenNet/nautilus/commit/046c705d1dc0f1860bb3b634a68014b2a63a4c6e))
* config the operator sets now reaches the code that should read it ([24026fc](https://github.com/KrakenNet/nautilus/commit/24026fc6252d560cdd2963cf50c76ffc2ca339be))
* every governance decision reaches the audit log (UPSTREAM I) ([05d81bd](https://github.com/KrakenNet/nautilus/commit/05d81bd024b01b12ec3975990c585172a99efd86))
* every surface vets a forwarded subject, and the console filters (WAVE 13) ([8c87842](https://github.com/KrakenNet/nautilus/commit/8c8784264fd85bc0dc0ff17116af752de19a8c44))
* four advisories closed, and pyright taken from 142 to 0 (WAVE 18) ([17ad3d0](https://github.com/KrakenNet/nautilus/commit/17ad3d065a102146afd4083bfcb9dedb54507881))
* four answers that told the operator the wrong thing (WAVE E23) ([84a2da2](https://github.com/KrakenNet/nautilus/commit/84a2da2d4da64ec9c658443c9b8e13cca43bc121))
* make the shipped rule packs actually loadable ([52b8e91](https://github.com/KrakenNet/nautilus/commit/52b8e9136dd9bf703ec026127dde4e073b3b8c1c))
* one lock connection per request, and a probe that answers (WAVE E1) ([9d0e9db](https://github.com/KrakenNet/nautilus/commit/9d0e9dbaa316ea835e63eaa950cd417baca5049f))
* one mistake, one exit code, and two claims the CLI could not keep (WAVE E22) ([9c857a3](https://github.com/KrakenNet/nautilus/commit/9c857a3878260d93de0a351dd22bc59b28b469fe))
* one reader for the key, one filter for the catalogue (WAVE 15) ([3aef006](https://github.com/KrakenNet/nautilus/commit/3aef00675b98ee3705e369ccfc2c13a813685a15))
* persist the session slots the policy engine reads ([cb24954](https://github.com/KrakenNet/nautilus/commit/cb24954dd2ae4be9e26dacc4f71a212bf9f2fff2))
* production defaults that fail closed, and docs that match the package (WAVE A) ([3b70247](https://github.com/KrakenNet/nautilus/commit/3b702474749b0cc381435a9485c416d710ea63b1))
* prove the proposal path landed inside the queue, don't just describe it (WAVE 20) ([2bc0910](https://github.com/KrakenNet/nautilus/commit/2bc09105c801c5cc74c210a374dca5f6f9b9a55d))
* purpose-TTL expiry denies sources instead of crashing the router ([ac0f5e2](https://github.com/KrakenNet/nautilus/commit/ac0f5e21effca5540f0ae6b38f7cefba8a413d21))
* refresh the lock the 41 advisories were all pinned behind ([91ea8bd](https://github.com/KrakenNet/nautilus/commit/91ea8bdba25c2f8cbae3f043ce3233d84cb77794))
* refresh the lock the 41 advisories were all pinned behind ([7091e27](https://github.com/KrakenNet/nautilus/commit/7091e2749300e1453a2803243db66a1542e210e7))
* schema baselines cannot name a path, and tests cannot share one ([4947ff6](https://github.com/KrakenNet/nautilus/commit/4947ff6d83b3aedee381cd1094ec6fdbdf29adea))
* sibling 404s now name the thing before "not found" (WAVE E24) ([2e7451f](https://github.com/KrakenNet/nautilus/commit/2e7451fa46450db5ae29ce2c6b04995ea1aa20ea))
* surfaces that reported success they had not established (WAVE 16) ([def5a2c](https://github.com/KrakenNet/nautilus/commit/def5a2c4ebf190f7921e3b914349e74f9b4876c4))
* tests that could not fail, and the example they were not running ([021c4bd](https://github.com/KrakenNet/nautilus/commit/021c4bd78607b1e19646f7491be15446ce335a14))
* the adapter SDK builds adapters the broker will actually accept (WAVE 2) ([ad506e8](https://github.com/KrakenNet/nautilus/commit/ad506e81ad1893278f79d9ccf567bef7001594d9))
* the admin console is opt-in, and enforces what /v1/request enforces (WAVE E3) ([f3d784c](https://github.com/KrakenNet/nautilus/commit/f3d784c53b7a4520cc062fc918b497fbe785e1da))
* the agent registry decides clearance, not the caller ([91de756](https://github.com/KrakenNet/nautilus/commit/91de7560ca7673c94e3ef6237a39214b9dbe5fc5))
* the audit entry tells the truth about what the request did ([3553134](https://github.com/KrakenNet/nautilus/commit/35531340dac3f51521f6b1362649393cef879312))
* the broker sheds load instead of hanging, and bounds what a source can hand it (WAVE B2) ([61ac44c](https://github.com/KrakenNet/nautilus/commit/61ac44cc368903c414ffabdabd39acca75dbd2a7))
* the catalogue, the counters and the demo say what is actually true (WAVE E14) ([cb4a75e](https://github.com/KrakenNet/nautilus/commit/cb4a75eff3fa11e527488cb7b7ffba133706c3b3))
* the CLI credential stops going through argv (WAVE 9) ([36d10b2](https://github.com/KrakenNet/nautilus/commit/36d10b236659ce2407fddd7791c51eb020b5fcb6))
* the CodeQL sweep, closed alert by alert (WAVE 19) ([e58f521](https://github.com/KrakenNet/nautilus/commit/e58f521b157df9dae87bd6ad9b45ee5587823e13))
* the compliance gate certified adapters that enforce nothing (WAVE E19) ([db21391](https://github.com/KrakenNet/nautilus/commit/db213910dda333310fd6d3cd4c5222c7e12db70b))
* the escalation packs have a consumer (UPSTREAM M) ([0765177](https://github.com/KrakenNet/nautilus/commit/0765177077bbe1c1073d7fb85bdd7c5e24b14cd3))
* the exposure ledger follows the caller, and the receipts say what they mean (WAVE 6) ([4c048b7](https://github.com/KrakenNet/nautilus/commit/4c048b78f65f8a2fc323b4b8e39bb6e2f98e2dad))
* the four security majors — one door, one clearance, one hash, one bound (WAVE E6) ([ebede1e](https://github.com/KrakenNet/nautilus/commit/ebede1ea774b2f9cb7a1f5bafdf4a7557f47ce84))
* the front door works, and refuses what it says it refuses (WAVE E12) ([785d496](https://github.com/KrakenNet/nautilus/commit/785d496aa2d57987b2b10c4ddc955595467f0b50))
* the guards from WAVE 15 and 16 were the wrong shape (WAVE 17) ([4f32bc8](https://github.com/KrakenNet/nautilus/commit/4f32bc8b1d5a82be8d783045ec959235865557e2))
* the image says which extras it carries, and failures name a remedy you can perform (WAVE 14) ([2011aa4](https://github.com/KrakenNet/nautilus/commit/2011aa4a386c20b9f22397bf3e6497724b3c6c9f))
* the operational surface reports what it is doing (WAVE 4) ([a35e505](https://github.com/KrakenNet/nautilus/commit/a35e5050e6d54b6192468111e64e9e777e7d48aa))
* the operational surface tells the truth about what it did (WAVE B3) ([591a700](https://github.com/KrakenNet/nautilus/commit/591a700473895554c2f837361d4ddd4f26750177))
* the package a stranger installs is the one CI tests (WAVE E4) ([0746acd](https://github.com/KrakenNet/nautilus/commit/0746acdf3aaaa422fe4952e858877acb6eac264b))
* the request that fails is the request that names what broke (WAVE 12) ([9242cd7](https://github.com/KrakenNet/nautilus/commit/9242cd776362fae124f8843b782f5b11270ecf99))
* the response says what happened and why (WAVE C1) ([ad9ec5a](https://github.com/KrakenNet/nautilus/commit/ad9ec5a855848c4925f835ed045c7eb6938fdbc8))
* the response says which refusals were about the request (WAVE E7) ([ff5dd13](https://github.com/KrakenNet/nautilus/commit/ff5dd134e2f1ffb8782919f91f19f09d956cc9d6))
* the RKM proposal queue's readers and writers now agree ([1b0b507](https://github.com/KrakenNet/nautilus/commit/1b0b507029d1a81be7a482d35547a38f9aba4e55))
* the RKM validators now run against a real engine ([06301df](https://github.com/KrakenNet/nautilus/commit/06301df1ff177a52d3f3d3235ecbdb88035697ad))
* the rule-authoring toolchain answers about the rules that ship (WAVE 3) ([5a3563a](https://github.com/KrakenNet/nautilus/commit/5a3563a8e2c6bbc161b8d4813c703b6f032b1323))
* the schema-drift gate can actually fire ([799f328](https://github.com/KrakenNet/nautilus/commit/799f328d2b139d6e4cd4dcfce4f1b84ad6368586))
* the shipped deployments can write, and MCP fits in a context window (WAVE E5) ([ec1859a](https://github.com/KrakenNet/nautilus/commit/ec1859a381abe7d88976050786307de958488e12))
* the type checker CI runs is green ([9613210](https://github.com/KrakenNet/nautilus/commit/96132104f26d371c0913a2ebb1971bdf91880805))
* three claims the repo makes that were not true (WAVE E16) ([9f66f07](https://github.com/KrakenNet/nautilus/commit/9f66f07035fa349a374c62483712851d4fc5dffb))
* three credentials and receipts that travelled quietly (WAVE E20) ([b606430](https://github.com/KrakenNet/nautilus/commit/b606430d9341ad050fea085881d0cacb8d6050ea))
* three defects the doc builders found while writing about them (WAVE E17) ([c2e6cee](https://github.com/KrakenNet/nautilus/commit/c2e6ceee9b82e4662b055dd432cf219a4c8420e8))
* two replicas, and two boots, tell the truth (WAVE E2) ([5fb69bf](https://github.com/KrakenNet/nautilus/commit/5fb69bf2d5e55396bfb5f354d75d0c7a87137ec8))
* unblock the 0.3.0 release PR on all three of its own gates ([0761cda](https://github.com/KrakenNet/nautilus/commit/0761cdade7058324dcf57c35f25f9b1007cc5db0))
* unblock the 0.3.0 release PR on all three of its own gates ([ea4f77a](https://github.com/KrakenNet/nautilus/commit/ea4f77a36a2f113b43939a9f1952e7741e3cc018))
* wave 0 — the one-line safety fixes (B1, B2, B4, B5, B6, B7, 4.12) ([733b9cb](https://github.com/KrakenNet/nautilus/commit/733b9cbbab0d456a7796c8b6d1b0184a64431295))
* wave 1 — concurrency and lifecycle (4.1, 4.2, 4.18, 4.22, B3) ([a9da7d9](https://github.com/KrakenNet/nautilus/commit/a9da7d969d896332d6448062c37a1de1242ab30d))
* what is signed, stored and shipped says what it is (WAVE E11) ([565d083](https://github.com/KrakenNet/nautilus/commit/565d08383a7cd229d83b9f562bb13c02ad083294))
* when a source dies the broker names it, and the SSRF guard covers names (WAVE 11) ([1e34408](https://github.com/KrakenNet/nautilus/commit/1e34408e79d9029fbd92cd9a2fba87ca5898a7c6))


### Documentation

* document the surface that actually exists (GAUNTLET WAVE 1) ([f156908](https://github.com/KrakenNet/nautilus/commit/f156908ad74cad0da1b310bd6166f72f10095a33))
* every in-container procedure now runs in the image we actually ship (WAVE 12) ([7fffc6e](https://github.com/KrakenNet/nautilus/commit/7fffc6e567eb9824ef936dabfe66deec99e6eb91))
* the authority the documentation names is one a reader can reach (WAVE 14) ([11d7848](https://github.com/KrakenNet/nautilus/commit/11d78487998362a46cb8d623504dbf36988d7ec2))
* the citation lock closes, and 22 citations were wrong about the code (WAVE 13) ([02a4db3](https://github.com/KrakenNet/nautilus/commit/02a4db34218981ce3540758c067686184df2cdae))
* the error pages stop describing a redactor the code no longer has (WAVE 12) ([47cc3cd](https://github.com/KrakenNet/nautilus/commit/47cc3cdd2047d3b99faf9ce2eed1f52f69f20a38))
* the operator surface, written from what the code does (GAUNTLET WAVE 2) ([59d5b31](https://github.com/KrakenNet/nautilus/commit/59d5b31d42654d5eff3027a85d1ee0f26501ffb0))
* the probe pages described the behaviour WAVE 16 replaced (WAVE 16b) ([106cef0](https://github.com/KrakenNet/nautilus/commit/106cef01573817847953b08e68e41e506d39369c))
* the reload procedure's log lines match what the published unit emits (WAVE 8) ([bceddbb](https://github.com/KrakenNet/nautilus/commit/bceddbbb810d740c0025505d65a0e0e4e8c80d3f))
* the reload WAVE 12 shipped is now one an operator can actually reach (WAVE 13) ([fbd931a](https://github.com/KrakenNet/nautilus/commit/fbd931a8fb03786b6d29db71eb59accf938562c7))
* write down the trust boundary the guarantees rest on (WAVE B4) ([a9c1467](https://github.com/KrakenNet/nautilus/commit/a9c14672a5f509c7a5a63b76e51ab70673617b31))

## [0.2.5](https://github.com/KrakenNet/nautilus/compare/v0.2.4...v0.2.5) (2026-07-20)


### Bug Fixes

* stop embedding literal '?' in InfluxDB containsStr substring for LIKE patterns ([#110](https://github.com/KrakenNet/nautilus/issues/110)) ([#160](https://github.com/KrakenNet/nautilus/issues/160)) ([3074387](https://github.com/KrakenNet/nautilus/commit/3074387448bcb26e0667b7b4cfbc231c8e13f9e0))

## [0.2.4](https://github.com/KrakenNet/nautilus/compare/v0.2.3...v0.2.4) (2026-06-29)


### Documentation

* align README documentation link text ([2858fd1](https://github.com/KrakenNet/nautilus/commit/2858fd1e6689e11196779b7f2df74a90ece10542))

## [0.2.3](https://github.com/KrakenNet/nautilus/compare/v0.2.2...v0.2.3) (2026-06-26)


### Documentation

* correct SourceConfig.type comment to match closed Literal ([#138](https://github.com/KrakenNet/nautilus/issues/138)) ([5c71810](https://github.com/KrakenNet/nautilus/commit/5c718101bb2f5e8ecd567ac4f7db1ec5d9a241a5))

## [0.2.2](https://github.com/KrakenNet/nautilus/compare/v0.2.1...v0.2.2) (2026-06-25)


### Documentation

* fix doubled slash docs URLs ([#133](https://github.com/KrakenNet/nautilus/issues/133)) ([84a3e0e](https://github.com/KrakenNet/nautilus/commit/84a3e0ecad21c6053d681be16a7f42146d34510f))
* fix HIPAA rule-pack entry point ([#134](https://github.com/KrakenNet/nautilus/issues/134)) ([7a67868](https://github.com/KrakenNet/nautilus/commit/7a67868ed4104dab4ab2d782068c636e5228d544))
* fix quickstart Python version ([#132](https://github.com/KrakenNet/nautilus/issues/132)) ([32eacbf](https://github.com/KrakenNet/nautilus/commit/32eacbf2be0c2f6fe819626209059474be605ec6))
* update current version in README ([#135](https://github.com/KrakenNet/nautilus/issues/135)) ([48083bb](https://github.com/KrakenNet/nautilus/commit/48083bbaeead2149c061f1f72044e121c05b2a6d))

## [0.2.1](https://github.com/KrakenNet/nautilus/compare/v0.2.0...v0.2.1) (2026-06-24)


### Bug Fixes

* **ci:** repair invalid Dependabot cooldown (semver-*-days unsupported for non-semver ecosystems) ([#71](https://github.com/KrakenNet/nautilus/issues/71)) ([af70491](https://github.com/KrakenNet/nautilus/commit/af70491fa353fd7fe361b250d269fd6c77be81d2))
* use `cooldown.default-days` only — valid for every ecosystem. Validated against Dependabot's own config check on this PR before merge. ([af70491](https://github.com/KrakenNet/nautilus/commit/af70491fa353fd7fe361b250d269fd6c77be81d2))

## [0.2.0](https://github.com/KrakenNet/nautilus/compare/v0.1.3...v0.2.0) (2026-06-24)


### Features

* **analysis:** auto-generate intent vocabulary from SourceConfig.data_types ([#24](https://github.com/KrakenNet/nautilus/issues/24)) ([#44](https://github.com/KrakenNet/nautilus/issues/44)) ([3a71374](https://github.com/KrakenNet/nautilus/commit/3a7137470ca9c4d462006a5a0426f9d899e1f9b8))
* **attestation:** live signing-key rotation + lazy token re-sign ([#25](https://github.com/KrakenNet/nautilus/issues/25)) ([#47](https://github.com/KrakenNet/nautilus/issues/47)) ([9072760](https://github.com/KrakenNet/nautilus/commit/9072760b5837ef092ddf7c4a445ed282646aa666))
* **attestation:** per-source adapter response hashing + attestation linkage ([#19](https://github.com/KrakenNet/nautilus/issues/19)) ([cb5808a](https://github.com/KrakenNet/nautilus/commit/cb5808a2cbecda3de450e44aefdfc8be4ad83601))
* **attestation:** session-token plumbing — issue, verify, handoff gate, audit events ([#46](https://github.com/KrakenNet/nautilus/issues/46)) ([dee0fdc](https://github.com/KrakenNet/nautilus/commit/dee0fdcd3e2cc2605604e6c529ee165418ba553f))
* **core:** post-run engine consistency checks ([#27](https://github.com/KrakenNet/nautilus/issues/27)) ([#48](https://github.com/KrakenNet/nautilus/issues/48)) ([5bd75a9](https://github.com/KrakenNet/nautilus/commit/5bd75a9329b0905dc102d599baf112636ecdb943))
* **core:** SQLite session store + durable Postgres fallback ([#26](https://github.com/KrakenNet/nautilus/issues/26)) ([#49](https://github.com/KrakenNet/nautilus/issues/49)) ([09eb768](https://github.com/KrakenNet/nautilus/commit/09eb76812fe81303186e698b22ae1c0a9b854825))
* **observability:** structured JSON logging ([#28](https://github.com/KrakenNet/nautilus/issues/28)) ([#50](https://github.com/KrakenNet/nautilus/issues/50)) ([bc577ad](https://github.com/KrakenNet/nautilus/commit/bc577adcf4bbd61cba75d69566209adc2cf25a58))
* **servicenow:** attachment-content fetch for sys_id-pinned sys_attachment queries ([245d1b0](https://github.com/KrakenNet/nautilus/commit/245d1b0fe0515366ba9ab6ab0daed4de6b6ca992))
* **transport:** public REST API for audit queries ([#32](https://github.com/KrakenNet/nautilus/issues/32)) ([#45](https://github.com/KrakenNet/nautilus/issues/45)) ([3b8e407](https://github.com/KrakenNet/nautilus/commit/3b8e407fede1b7d09991571b5b30b44e5dc51caf))


### Bug Fixes

* **attestation:** document capabilities contract instead of typing it (fix CI pyright) ([35019c3](https://github.com/KrakenNet/nautilus/commit/35019c388b4c510c9bcd56cebac828601a444a9c))
* **attestation:** never trust adapter-supplied response_hash; persist per-source digests to audit ([f80d333](https://github.com/KrakenNet/nautilus/commit/f80d333857412043d6c6157861092f39bd9cdf90))
* **attestation:** per-source adapter response hashing + attestation linkage ([b2c450b](https://github.com/KrakenNet/nautilus/commit/b2c450b10ccbbf7ce203e6606ccb2631ed069e97))
* **attestation:** record per-source digests on primary audit entry; declare capabilities contract ([bb25179](https://github.com/KrakenNet/nautilus/commit/bb251792d1e5c3d4dba4c1027f71540793cbc948))
* make onboarding guide runnable and prometheus import optional ([ae99b39](https://github.com/KrakenNet/nautilus/commit/ae99b39a4d49af3c77bc47b122721c17c0b1cae0))
* make onboarding guide runnable and prometheus import optional ([f8c70ed](https://github.com/KrakenNet/nautilus/commit/f8c70ed2c9d1eb0b9678051342118a14dc0a8fc5))
* **meta:** crisper description, repair dead docs URL, enrich keywords/classifiers, add llms.txt ([#69](https://github.com/KrakenNet/nautilus/issues/69)) ([58c4b6d](https://github.com/KrakenNet/nautilus/commit/58c4b6d510649c8a99f23d03f40232d427cfb89b))
* Py2 except-syntax bugs blocking import + bump to 0.1.4 ([e25a712](https://github.com/KrakenNet/nautilus/commit/e25a712f979beeda1d8f8781cbeb8dd5201a1a02))
* re-apply except-paren fixes + lower ruff target-version to 3.13 ([685ebe6](https://github.com/KrakenNet/nautilus/commit/685ebe6f8477f3cf3810f4e2f098f927cde3e831))
* replace Py2 'except A, B:' with Py3 'except (A, B):' ([1ff8d58](https://github.com/KrakenNet/nautilus/commit/1ff8d584665fcd45e2860e1471707e6c13344ebe))
* sync nautilus/__init__.py __version__ to 0.1.4 ([b32fb7b](https://github.com/KrakenNet/nautilus/commit/b32fb7b11b7230efa297e6091ddaafac751a813c))


### Documentation

* operator guide, rule-authoring guide, recipes, concepts ([#33](https://github.com/KrakenNet/nautilus/issues/33)) ([#54](https://github.com/KrakenNet/nautilus/issues/54)) ([bd3140c](https://github.com/KrakenNet/nautilus/commit/bd3140c2c8c4531889c1374fa733c959eba38136))
* **rest:** clarify NOT IN default builder is fail-closed, not a stub ([377a962](https://github.com/KrakenNet/nautilus/commit/377a962c6871fe199640143278a55d1f6e831df5))
* update harbor references to stargraph after repo rename ([730c440](https://github.com/KrakenNet/nautilus/commit/730c440eb70c306b7485d0117a768e05317b5c9e))

## [0.1.5] - 2026-05-01

### Added
- `BrokerRequest.fact_set_hash` and `Broker.{request,arequest}(..., fact_set_hash=...)` keyword surface so callers can pin a request to a specific fact-set snapshot
- `BrokerResponse.fact_set_hash` echoes the caller's hash back on success
- `BrokerResponse.cap_breached` and `BrokerResponse.source_session_signatures` re-introduced (defaulted `None`) for forward-compat with budget-cap and per-source signature surfaces

## [0.1.4] - 2026-05-01

### Fixed
- Restore Python 3.13 compatibility: replace bare `except A, B:` (Python 3.14 syntax) with `except (A, B):` in `analysis/fallback.py`, `forensics/handoff_worker.py`, `ui/router.py`, and `ui/audit_reader.py`
- Lower `[tool.ruff] target-version` from `py314` to `py313` to keep parens on multi-exception except clauses

## [0.1.1] - 2026-04-17

### Fixed
- CI badge and clone URLs updated to KrakenNet organization
- Documentation site links corrected
- CI workflows updated to trigger on `main` branch
- Documentation deployment workflow improvements

## [0.1.0] - 2026-04-17

### Added
- Core `Broker` facade with sync/async APIs (`request`, `arequest`, `from_config`, `afrom_config`)
- Fathom-based policy router for intent-aware source selection and scope enforcement
- Eight built-in adapters: PostgreSQL, PgVector, Elasticsearch, Neo4j, REST, ServiceNow, InfluxDB, S3
- Pluggable adapter protocol with entry-point discovery
- Ed25519 JWS attestation service for signed routing decisions
- JSONL audit sink with per-request append-only entries
- Pattern-matching and LLM-based intent analysis (Anthropic, OpenAI providers)
- Cross-agent handoff reasoning with session-backed escalation detection
- FastAPI REST transport (`POST /v1/request`, health/readiness probes)
- MCP transport (stdio and HTTP modes)
- CLI: `nautilus serve`, `nautilus health`, `nautilus version`
- YAML configuration with environment variable interpolation
- Rule packs: `data-routing-nist`, `data-routing-hipaa`
- Adapter SDK (`nautilus-adapter-sdk`) with compliance test suite
- OpenTelemetry instrumentation (optional `otel` extra)
- Air-gapped mode (`--air-gapped`) forcing pattern analyzer
