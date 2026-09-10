# BlockGO QA Test Report

Test date: 2026-09-04 (Asia/Singapore)  
Final security, monitoring, and infrastructure retest: 2026-09-06 (Asia/Singapore)  
Test source: [BlockGO Google Docs test cases](https://docs.google.com/document/d/14GdYC4cjNnD8PMuXaygP0iePptNjlPeJVZqwPLHdM1Y/edit?tab=t.0)  
Environment: local Kubernetes deployment at `http://localhost:8080`

## Executive result

| Result | Count |
|---|---:|
| Pass | 57 |
| Fail | 30 |
| Blocked for shared-data safety | 5 |
| Total cases in the document | 92 |

The document contains 14 Student, 23 Faculty, 12 Chairperson, 20 Registrar, and 23 Administrator cases. `TC-F-017` is not present in the source document, so it is not included in the count.

The frontend, .NET gateway, and middleware readiness endpoints returned HTTP 200. The deployment is usable, but it is not production-ready because approval/finalization guards can still be bypassed, closed-period rules remain client-only, and the grade-upload/final-ledger expectation is not yet met. Login throttling, ledger-service stability, blank/duplicate grade validation, Chairperson lookup/bulk-curriculum APIs, and the local HA data plane were fixed and retested on 2026-09-04. The automatic-ID/manual-enrollment repair described below passed source builds and automated regression tests and awaits a live acceptance run.

## Test approach

- Ran all repository automated tests: 16/16 middleware tests and 47/47 frontend tests passed. The suites include failed-login isolation, serialized Fabric operations, atomic curriculum-import parsing, Registrar enrollment, current-semester/on-demand blockchain disclosure, Registrar and System Administrator transaction-pagination regressions, realtime transaction refresh, protected monitoring, password-change requests, and safe shared authentication/API-notification behavior.
- Exercised the deployed UI in headless Chrome for Registrar, Student, Faculty, Chairperson, and System Administrator roles.
- Exercised authenticated APIs using dedicated `qa-*` accounts, two dedicated students, a support ticket, and 51 dedicated grade records.
- Uploaded a 50-row grade file, duplicate rows, blank-ID rows, unsupported PDFs, a Gregorian leap-day student, and an unapproved grade finalization attempt.
- Checked PostgreSQL state, student ledger visibility, authorization responses, Fabric/orderer/peer logs, Kubernetes readiness, and restart reasons.
- Did not execute global season reset or replace the active encoding schedule because those operations would delete shared assignments/pending grades or disrupt the current dataset. Those cases are marked Blocked where no safe isolated equivalent existed.

## Enrollment template and UI follow-up — 2026-09-07

### Optional section numbers and post-enrollment assignment

- Added optional **Section Number** to the downloadable CSV template and CSV/XLSX backend import. Positive integers resolve against the selected year level (default 1st Year); blank values leave section/academic section unset for later assignment. Legacy full Section values remain supported; conflicting columns and invalid numbers report specific errors.
- Added Section display and an Assign control to Current Student Enrollments. Assignments use the student's saved program, year level, school year, and semester rather than the upload form's potentially changed selection.
- Reviewed the existing transactional ID allocator: school-year start determines the prefix, with a separate sequence per enrollment year (2026 => 26-xxxx; 2027 => 27-xxxx). Sequences start at 0001; existing/reserved IDs are not reused, so gaps after failed uploads are possible. Section assignment preserves the ID.
- Created Downloads/student-enrollment-2026-2027-optional-sections-test.csv with six synthetic students: two 1-1, one 1-2, and three blank sections. No ID/password columns. Select an existing program, School Year 2026-2027, 1st Year, and 1st Semester, then upload. Assign a blank section from the enrollment table afterward.
- Validation: all 68 frontend tests passed; after adding the downloadable-template assertion, the six enrollment-component tests passed. Production frontend build succeeded. Backend parser checks passed against both the supplied original 21-row CSV and the new six-row CSV, including invalid/conflicting section cases. Backend image compiled successfully with existing nullable warnings. These checks do not perform a full authenticated enrollment or create student accounts.
- Local images: frontend:blockgo-optional-sections and client-app:blockgo-optional-sections. Frontend build: main.1b9c4114.js.

- **Sectionless enrollment follow-up:** a subsequent real upload exposed a downstream rule that the earlier CSV-parser checks did not exercise: `NormalizeEnrollmentSection` required a section even though the template intentionally omits it. Manual/bulk enrollment now permits a blank section and stores no section assignment; explicitly supplied sections still require a valid year-section format matching the selected year. Explicit section-assignment actions retain their required-section validation. New checks cover blank sections for years 1–4, valid sections, malformed/year-mismatched sections, and sectionless validation of all 21 supplied rows. The live schema was verified to allow NULL `StudentProfiles.section`, `student_enrollments.section`, and `academic_section_id`. The replacement image is `client-app:blockgo-sectionless-enrollment-fix`; no supplied records were imported by these regression checks.
- **Root cause fixed:** the downloaded enrollment template uses `Birthdate`, while the backend previously looked up only `birthday`, `dob`, and `date_of_birth`. CSV and XLSX headers now normalize those aliases, including `Birth Date`, to the same field. Neither manual nor bulk student enrollment requires a password column.
- **CSV parsing fixed:** enrollment now uses the existing CsvHelper dependency instead of splitting each line on commas/semicolons. Quoted commas, multiline addresses, UTF-8 BOMs, and supported delimiters are preserved. Empty files, duplicate headers, and inconsistent column counts return validation errors before enrollment starts.
- **Supplied file checked:** `student-enrollment-2026-2027-with-20-added.csv` passed the backend parser with 21 student rows and valid names/birthdates. A read-only account lookup found zero existing accounts matching its supplied emails. No supplied students were imported or enrolled during these checks.
- **Unnecessary popups reduced:** background GET/HEAD requests and shared-state synchronization no longer dispatch global error popups; callers still receive errors. Visible duplicate notifications are suppressed beyond the old 1.5-second debounce. Monitoring retains the same error through failed polling attempts, and enrollment ID previews no longer reload after every validation/result change. Initial monitoring loading no longer mounts/unmounts the ledger unnecessarily.
- **System Administrator ledger:** Infrastructure & Data displays finalized grades in a visible, horizontally scrollable table with Student, Subject, Grade, Class, Faculty, Finalized, and Transaction columns. Removed the duplicate card layout, retained pagination, and added Refresh ledger.
- **Validation:** all 19 frontend suites / 66 tests passed; the frontend production build passed; the .NET Release container build passed (existing nullable-reference warnings remain). Executable backend parser checks passed for birthdate aliases, quoted/multiline values, delimiters, malformed/empty files, and the supplied CSV.
- **Local deployment:** rolled out `client-app:blockgo-enrollment-header-fix` to `dotnet-auth-service` and `frontend:blockgo-enrollment-ledger-fix` to `frontend` in the Docker Desktop `plv-fabric` namespace. Both deployments are Ready. Restored the local frontend port-forward; `/nginx-health`, `/`, and `/api/backend/health` returned HTTP 200 at `http://localhost:8080`, serving `main.d7fd1940.js`. Previous deployment definitions are saved in `.git/enrollment-fix-deployments-before.json`.

These checks validate the file/parser contract and local deployment; they do not claim a completed live database/Fabric enrollment for the supplied students. The earlier critical backend findings below remain separate.

## Critical and high-priority defects

1. **Authorization workflow bypass:** Registrar finalization accepted a returned/unapproved QA grade with HTTP 200 and wrote it to the ledger. `TC-R-013` fails.
2. **Grade upload does not meet the ledger expectation:** the 50-row upload reported 50 successes but created 50 PostgreSQL drafts and zero finalized ledger markers.
3. **Closed-period rules are client-only:** grade record, override, submit, finalization, and reset endpoints do not enforce the encoding period. Finalization succeeded while the period was active; reset has no active-period guard.
4. **Non-password operational email delivery:** older account/assignment notification attempts logged SMTP `5.7.0 Authentication Required`. Password changes no longer depend on SMTP or OTP, but any remaining account/assignment-email expectations require separate verification.

## Resolved and retested on 2026-09-04

- **Enrollment and role UI repair deployed (2026-09-05; data-mutating acceptance still pending):** manual enrollment and blank-ID bulk rows now use a PostgreSQL advisory-lock-backed `YY-0001` through `YY-9999` allocator keyed by Gregorian enrollment year; explicitly supplied bulk IDs remain unchanged. Each student/staff upload returns a batch ID. Student email login is rejected in favor of Student ID. Registrar staff creation now supports CSV/XLSX batches. Chairperson Faculty-section tagging is department-scoped and browser state is saved only after backend success. Registrar curriculum decisions are labeled as whole-program-version actions. Student grades use current curriculum subjects for a current-semester dropdown, hide transaction proof until explicitly requested, and show professor/committing Registrar metadata. The migration and replacement .NET, auth, and frontend images are live; a protected Registrar probe returned `27-0001` for an empty 2027 sequence and the deployed bundle contained all new controls. .NET Release Docker build, frontend production build, Go chaincode compile, 44/44 frontend tests, 16/16 middleware tests, and local deployment-source verification passed. Creating official Student/Faculty records was intentionally left for a designated QA batch.
- **Department Head batch curriculum assignment deployed (2026-09-06):** curriculum assignment is stored once per academic program and Gregorian intake year, is reused by manual and bulk Registrar enrollment, and remains active until that program's Department Head explicitly changes it in Curriculum Builder. Registrar per-student curriculum assignment is disabled. Migration `012` backfilled existing profile/enrollment batch years and is included in the production/local deployment migration gate. A protected live BSEE probe returned batch 2026 with 2 students assigned to published curriculum `2026-E2E`.

- **Login throttling:** six consecutive successful System Administrator logins from one source returned HTTP 200. Five failed attempts for one normalized account returned HTTP 401 and the sixth returned HTTP 429; a different account from the same source still returned HTTP 401 rather than being locked. HTTP 5xx authentication-service failures are excluded from the attempt budget by regression test.
- **Ledger-service memory/TLS behavior:** concurrent Gateway creation is coalesced per normalized identity, operations per cached identity are serialized, discovery is opt-in, cache capacity is 12, idle eviction is 60 seconds, and partially initialized Gateways are disconnected on error. Readiness validates endpoint/TLS configuration without opening raw TLS sockets and caches wallet checks. Twelve simultaneous ledger reads returned 12/12 HTTP 200 through one cached Gateway; the replacement pod remained Ready with zero restarts and no TLS EOF/reset entries from its IP. The pod limit is now 768 MiB. A longer production soak is still recommended.
- **Grade validation:** an upload containing a missing Student ID and a missing active-term grade returned `totalProcessed: 2`, `successful: 0`, and `failed: 2`, including row-numbered reasons. Repeating an existing manual Student+subject offering returned HTTP 409 and did not update the record.
- **Chairperson APIs and curriculum import:** approved Student and Faculty lookups now authorize `department_admin` and scope results to that administrator's department. Missing optional settings return a nullable default instead of a false-positive 404. Curriculum CSV imports now use one transactional bulk endpoint, reject invalid/duplicate rows before committing, and support multiple prerequisites. Authenticated live probes returned HTTP 200 for all Chairperson list endpoints; the empty bulk request correctly returned HTTP 400.
- **HA and deployment isolation:** all three primary peers and all three secondary peers joined `registrar-channel` and reported block height 196. Secondary health checks use the HTTP operations port, and gossip advertises certificate-matching peer names with cross-namespace aliases; the final log sample contained zero TLS-handshake or gossip-connection failures on all six peers and all three orderers. The five PostgreSQL standbys were Running and Ready under WAL-receiver-aware probes, while the primary reported five replication connections. CouchDB services remain internal `ClusterIP` services; the localhost tunnel implementation for ports 5986, 5990, 6990, and 7990 was removed from the deployment script, while cleanup still terminates tunnels created by older deployments.
- **Automated delivery controls:** consolidated TDD, CodeQL, dependency review, production dependency audit, deployment-contract, strict route-smoke, and threshold-enforced XP stress jobs validate `Backup-2`, `Staging-and-Testing`, and `main`. GitHub-native governance configures the required `quality-gate` branch protections, while a reusable promotion workflow permits only `Backup-2 -> Staging-and-Testing -> main`. Staging reruns the complete suite after promotion before it can open the `main` pull request. Local `actionlint` and deployment-source verification passed. Frontend runtime dependencies reported zero vulnerabilities; middleware runtime dependencies reported zero high/critical findings, with five low-severity findings remaining in the Fabric SDK/Express dependency tree.
- **Migration cleanup:** the successful PostgreSQL migration job was retained and its stale failed-attempt pod was removed on 2026-09-05. No non-serving Error pods remained after the final infrastructure sweep.
- **Grafana access:** the System Administrator session endpoint returned HTTP 200 and the authenticated same-origin proxy returned Grafana `/api/health` with HTTP 200 and `database: ok`. Grafana remains an internal `ClusterIP`; browser access uses the protected application proxy instead of a public port.
- **Finalized-ledger access control:** all peer-state and wallet CouchDB services remain internal `ClusterIP` services, and host ports 5986, 5990, 6990, and 7990 had no listeners. The System Administrator API exposes exactly one fixed source, `registrar-channel_registrar`, and returns finalized records as allow-listed grade fields. The UI now renders labeled, responsive grade cards and shortened ledger references instead of raw JSON/database documents. It provides no database selector, wallet data, MSP material, certificates, raw JSON, credentials, or mutation endpoint. An unauthenticated request returned HTTP 401; a wallet-path request returned HTTP 404.
- **Prometheus Live:** the containerized Prometheus pod remains Ready and internal-only. On 2026-09-06, the PostgreSQL 18 exporter HTTP 500 was traced to duplicate `pg_stat_replication` label sets from five identically named physical receivers. The conflicting legacy collector was disabled while the supported replication collector remained enabled, and readiness now validates `/metrics` instead of only the TCP port. The protected System Administrator endpoint returned `Success`, 21 healthy targets, and zero down targets; `pg_up` is 1.
- **Registrar-approved password changes:** the public Forgot Password UI and `/api/forgot-password` and `/api/reset-password` routes were removed; both legacy URLs returned HTTP 404. Migration 010 removed the OTP, expiry, and used-token fields and added request/decision/completion state. Only Faculty and Department Administrator roles can request from their authenticated headers; Registrar can list and approve/reject, and an approved requester sets the new strong password personally. System Administrator and Registrar request attempts returned HTTP 403, the Registrar list exposed no OTP fields, and no SMTP/OTP receiver participates in this flow.
- **System Administrator live transactions:** the protected `/api/SystemMonitoring/transactions` feed returned 250 newest-first records from `registrar-channel` with no source warnings: 29 committed Fabric world-state records and 221 application audit events. All 29 committed records carried valid 64-character Fabric transaction IDs. The UI refreshes on `AcademicDataChanged`, reconciles every three seconds, provides search/source filtering and ten-entry pagination, and switches to compact cards on mobile. Unauthenticated access returned HTTP 401 and Registrar access returned HTTP 403. After deployment, the frontend bundle and two successive advancing feed timestamps were verified, and every Deployment and StatefulSet returned Ready.
- **Frontend notifications:** authentication failures, validation failures such as missing upload columns, and legacy frontend alert messages now use one accessible popup stack. Popups provide explicit dismiss controls, timed exit handling, pop-in/pop-out animation, mobile sizing, reduced-motion behavior, and duplicate suppression. HTTP 5xx/technical database details are replaced with a safe system-level message; invalid-credentials, missing-column, internal-detail filtering, and dismissal regressions pass.

## Student cases

| ID | Result | Evidence |
|---|---|---|
| TC-S-001 | PASS | Registrar created a dedicated Faculty account; HTTP 201, Fabric identity creation completed, and Faculty login returned HTTP 200. |
| TC-S-002 | PASS | Registrar bulk-created two Student accounts/Fabric identities; both Student logins returned HTTP 200. |
| TC-S-003 | PASS | Duplicate Student ID upload was rejected at row level (`failed: 1`). |
| TC-S-004 | PASS | Browser login rendered the authenticated student's own ID and enrollment/profile card. |
| TC-S-005 | PASS | A Student querying another Student profile received HTTP 403. |
| TC-S-006 | FAIL | No one-subject failure notification exists; the UI starts warnings only at exactly two failed subjects. |
| TC-S-007 | FAIL | Academic warning UI does not include the failed subject, grade, or timestamp required by the case. |
| TC-S-008 | PASS | Passing equivalents do not enter the failed-subject warning calculation. |
| TC-S-009 | FAIL | Three failures render a warning, but they do not persistently flag/update the Student's academic status. |
| TC-S-010 | FAIL | The Student profile card has no persistent academic-warning/active-flag field. |
| TC-S-011 | FAIL | Warning removal is only recalculated from displayed finalized grades; there is no auditable automatic flag-removal workflow after correction. |
| TC-S-012 | PASS | Chat authorization permits Student-to-Registrar messaging and the chat UI is available to Students. |
| TC-S-013 | PASS | Registrar-to-Student messages feed the recipient event/unread-notification path. |
| TC-S-014 | PASS | Blank chat text is disabled in the UI and ignored by the hub. |

## Faculty cases

| ID | Result | Evidence |
|---|---|---|
| TC-F-001 | FAIL | Faculty landing has year tabs and section search, but no independent subject filter. |
| TC-F-002 | PASS | Year-level/All Sections controls rendered and filter section cards. |
| TC-F-003 | FAIL | There is no single Clear Filters action. |
| TC-F-004 | FAIL | When assigned sections exist but the search matches none, the filtered map becomes empty without a dedicated no-results message. |
| TC-F-005 | FAIL | 50-row upload accepted all rows but produced PostgreSQL drafts, not 50 ledger records. |
| TC-F-006 | PASS | Duplicate Student+subject rows in one upload produced one success and one rejected conflict. |
| TC-F-007 | PASS | PDF grade upload returned HTTP 400. |
| TC-F-008 | PASS | Blank Student-ID and blank active-term-grade rows are counted as failures with explicit row numbers and reasons (`2 processed, 0 successful, 2 failed`). |
| TC-F-009 | PASS | First manual subject grade was accepted with HTTP 200. |
| TC-F-010 | PASS | The same Faculty session/JWT remained active for the next subject operation. |
| TC-F-011 | PASS | Repeating the same Student+subject offering returned HTTP 409; the existing staged record was not overwritten. |
| TC-F-012 | FAIL | The deployed grade entry averages midterm/finals; the Formula Builder stores formulas but does not demonstrate the required quiz/midterm/final weighted computation in the encoding flow. |
| TC-F-013 | PASS | Submit Section returned HTTP 200 and moved 51 dedicated rows to `SubmittedToChairperson`. |
| TC-F-014 | PASS | Progress is calculated as encoded roster rows divided by total roster rows. |
| TC-F-015 | PASS | Faculty data refresh/realtime events recalculate progress after saves. |
| TC-F-016 | PASS | Assigned and empty-roster states render without a malformed page. |
| TC-F-018 | PASS | An active-period banner rendered using the saved active schedule. |
| TC-F-019 | FAIL | Warning starts at three days remaining, not the specified 48-hour boundary. |
| TC-F-020 | FAIL | UI can display Closed, but direct grade APIs do not enforce the closure. |
| TC-F-021 | PASS | Section/class summary export control is present. |
| TC-F-022 | PASS | Chair/Registrar review tables render Standing/Equivalent columns. |
| TC-F-023 | FAIL | Academic-status override accepts only a status; justification is not required or written to an audit record/ledger. |
| TC-F-024 | FAIL | Override API has no encoding-period check and can be called after closure. |

## Chairperson cases

| ID | Result | Evidence |
|---|---|---|
| TC-C-001 | PASS | Chairperson portal and Encoding Monitoring dashboard rendered. Its approved-Student, approved-Faculty, curriculum, program, and optional-setting requests were retested without HTTP 403/404/500 responses. |
| TC-C-002 | PASS | Faculty/section review rows are filterable in the rendered monitoring table. |
| TC-C-003 | BLOCKED | Requires starting a new global period/resetting shared cycle data; not executed against the active shared dataset. |
| TC-C-004 | BLOCKED | Review navigation rendered, but no same-department isolated Chairperson could be created because the only published-program Chair slot is occupied. |
| TC-C-005 | BLOCKED | Returning a grade as that existing Chair would affect non-QA ownership; shared return behavior was tested with a QA record under Registrar authority instead. |
| TC-C-006 | BLOCKED | Full return/correct/resubmit chain needs the same unavailable isolated published-program Chair context. |
| TC-C-007 | FAIL | Server return logic has no Finalized-status guard and can update a finalized ledger record to Returned. |
| TC-C-008 | PASS | Return notes are persisted on staged records and rendered in the review trail. |
| TC-C-009 | FAIL | A blank-note return was accepted by the API with HTTP 200; UI-only disabling is bypassable. |
| TC-C-010 | PASS | Review panel renders totals, pass/fail/INC/flagged summary and submitted-grade rows. |
| TC-C-011 | FAIL | Department forwarding changes status, but server-side Faculty correction does not reject approved/forwarded rows; lock is not authoritative. |
| TC-C-012 | FAIL | Approve/forward handlers do not verify complete roster grades before changing statuses. |

## Registrar cases

| ID | Result | Evidence |
|---|---|---|
| TC-R-001 | PASS | Registrar could query the combined ledger/staging view and see all 51 dedicated Faculty rows. |
| TC-R-002 | PASS | Student call to the grade-record write endpoint returned HTTP 403. |
| TC-R-003 | PASS | Registrar full academic/ledger query returned HTTP 200. |
| TC-R-004 | FAIL | There is no authoritative distribute-school-year-list action with a corresponding Chairperson notification/audit event. |
| TC-R-005 | PASS | Encoding schedule is saved and the current active period is readable by all role portals. |
| TC-R-006 | FAIL | A past end date changes UI state, but backend grade writes/submissions remain callable and no reliable recipient notification is enforced. |
| TC-R-007 | FAIL | Only one replaceable `encoding_period` value exists; there is no overlap model or validator. |
| TC-R-008 | PASS | Date-range activity query returned HTTP 200 in ordered form; no mutation endpoint exists for audit rows. |
| TC-R-009 | PASS | Export Log as PDF rendered in the browser. |
| TC-R-010 | PASS | Log empty/non-empty state rendered correctly. With 280+ rows, pagination rendered exactly five numbered buttons plus one last-page ellipsis and initially opened page 28. |
| TC-R-011 | PASS | Finalized dedicated record was removed from staging, written to the ledger, locked there, and became visible to the Student. |
| TC-R-012 | PASS | Student `/Student/grades` returned HTTP 200 with the dedicated finalized record. |
| TC-R-013 | FAIL | Registrar finalized a Returned/not-department-approved record with HTTP 200. |
| TC-R-014 | BLOCKED | Safely proving closed-period distribution would require replacing the currently active shared encoding schedule. |
| TC-R-015 | FAIL | Finalization succeeded while the encoding period was active; there is no active-period block. |
| TC-R-016 | PASS | Registrar finalized-grade PDF/report controls render and operate on ledger data. |
| TC-R-017 | FAIL | PDF export is available over the combined view and is not server-blocked when unfinalized rows are present. |
| TC-R-018 | PASS | Reset Encoding Season displays a confirmation prompt. |
| TC-R-019 | FAIL | Reset deletes pending grades and Faculty assignments; it does not archive the outgoing season before clearing it. |
| TC-R-020 | FAIL | Reset endpoint has no active-period guard and would execute during an active period. |

## Administrator cases

| ID | Result | Evidence |
|---|---|---|
| TC-A-001 | PASS | Valid System Administrator login returned HTTP 200 and rendered the administration portal. |
| TC-A-002 | PASS | A fresh invalid-password attempt returned HTTP 401. |
| TC-A-003 | PASS | Registrar accounts, support tickets, live blockchain transactions, infrastructure, alerts, observability, and chat controls rendered. |
| TC-A-004 | PASS | Registrar access to the System Administrator account API returned HTTP 403. |
| TC-A-005 | FAIL | System Administrator create-Faculty attempt returned HTTP 403; only Registrar may use that endpoint. |
| TC-A-006 | FAIL | System Administrator UI/API manages Registrars only; no Faculty deactivate action exists. |
| TC-A-007 | PASS | Registrar created a dedicated support ticket; HTTP 201. |
| TC-A-008 | PASS | Blank ticket description returned HTTP 400. |
| TC-A-009 | PASS | Administrator ticket list showed the dedicated ticket and required metadata. |
| TC-A-010 | PASS | Administrator changed status to `IN_PROGRESS`; Registrar read the same status. |
| TC-A-011 | PASS | Resolution with remarks persisted and was visible to Registrar. |
| TC-A-012 | PASS | Ticket list retained created/updated/resolved history fields. |
| TC-A-013 | PASS | Chat authorization permits System Administrator-to-Registrar only. |
| TC-A-014 | PASS | Registrar-to-System Administrator messaging and unread event handling are implemented. |
| TC-A-015 | PASS | Student, Faculty, and Chairperson roles are denied System Administrator chat targets. |
| TC-A-016 | PASS | Blank message submit is disabled and hub ignores whitespace. |
| TC-A-017 | PASS | Direct messages are encrypted and persisted in PostgreSQL for 30 days, with cache fallback. |
| TC-A-018 | PASS | Failed login attempts create security events visible through Administrator monitoring. |
| TC-A-019 | FAIL | Administrator alerts poll every 30 seconds; there is no realtime auth-service-to-admin alert event. |
| TC-A-020 | PASS | The sixth failed attempt for the same normalized account+source returned HTTP 429. Successful logins were not counted, and a different account on the same source retained its own attempt budget. |
| TC-A-021 | PASS | Security events are returned in deterministic newest-first timestamp order. |
| TC-A-022 | PASS | Normal successful login does not create a failed-login alert. |
| TC-A-023 | FAIL | No intrusion-report export control exists in the Administrator portal. |

## Deployment observations

- HTTP health/readiness: frontend, .NET gateway, middleware, PostgreSQL, CouchDB, IPFS, orderers, peers, and chaincode pods responded or reported Running.
- Fabric TLS: four historical server-side TLS EOF/reset messages appeared in the original 90-minute QA window—two on `orderer-1` and two on `peer-department`. After replacing raw TLS readiness handshakes, no TLS EOF/reset message was found from the replacement ledger-service pod IP during readiness and ledger-read retesting.
- `ledger-service`: the original pod reached 14 OOM restarts at its 512 MiB limit before replacement. The hardened 768 MiB pod completed 12 concurrent ledger reads with one Gateway cache entry and remained Ready with zero restarts during the post-fix test window.
- Alloy: Ready with the revised memory/probe settings; the earlier readiness timeout condition was not present during this retest.
- PostgreSQL migrations: the job completed successfully; its stale failed-attempt pod was removed during the final infrastructure sweep.
- The auth-service was replaced with the account+source failed-attempt limiter. Final middleware readiness returned HTTP 200.
- All six peers were channel-synchronized at block height 196. After replacing secondary TCP probes and correcting TLS-name/endpoint aliases, all six peers and all three orderers produced zero TLS-handshake or gossip-connection failures in the final post-rollout sample. The existing three-consenter local Raft ordering service is quorum-tolerant to one orderer failure; production manifests retain the six-orderer topology.
- Five PostgreSQL standby pods were Running and Ready after the replication-aware readiness probe rollout. Each standby reported recovery mode with an active WAL receiver, and the primary showed five connected replication clients.
- CouchDB has no NodePort/LoadBalancer/Ingress exposure and no deployment-managed localhost tunnel. Read-only inspection is available only through the authenticated System Administrator **Infrastructure & Data** view; manual localhost CouchDB addresses remain closed.
- Grafana reported `database: ok` through the authenticated System Administrator proxy at `/api/SystemMonitoring/grafana/`; direct unauthenticated proxy requests returned HTTP 401.

## Recommended fix order

1. Enforce state transitions server-side: Submitted -> DepartmentApproved -> Registrar Finalized, plus finalized immutability, nonblank return notes, completeness checks, and period guards.
2. Run live acceptance for automatic Student IDs/manual enrollment, batch staff upload, Student-ID-only login, Chairperson section tagging, program-level curriculum approval, and the current-subject transaction disclosure UI.
3. Verify any remaining account/assignment operational email notifications separately; password changes intentionally use no SMTP or OTP.
Did you get mean and behind open your camera said a while that we also said a while that thirdauthority and we also said thatchoice with having this statement U and R So therefore not P Q and R or not Q and R with the use of principles with the use of principle in this case it should become QR or Wright so it has not sit back U and R is true for discussed before the statement auxiliary you are so in this case we can decide I don't want to chance to get DF are truth to decide so therefore this particular principle of substitution using this compound statement is a proof that the hand letter and oxygen are gold UNR false false false folks are also statements that are the point and Justice in the hands about logically equivalent with they have the same results greater than q by the notation be by us in q are logically equivalents like this one these two and these two propositions are due different they are too different but they produce the same grup value falls through or taiwa or so we have falls through false false false through false statements but they have is a true value tax difference only if that also be it can also be represented using there are two day more than slow the first ones not the ordial not to follow on the mortgage law p and q by traditional not be or not quered law it will become the south mexico is not all in a timi or it does not in so I have here but using the divorce in skill number one conditional not be end not to convince us that the true propositions are logically evaluant to reduce this truth tables fused through false through false without force false through true and the next few and mango sports through okay na q the best started new kot so we have not be ar q so we have false false false he didn't so this is through this will become false okay this is through this will become false false and it will become so force force force or you by condition dare equivalent they are logically equivalent because they have the same truth values using the devoted flaw so if remove later they are logically equivalent using these mortgages so found this statement they can be ambivalent using the same organism to get that push to follow the market so we have not physically so ninna or by conditionalis not fee capadis for an additional we have through that q falls through the ballor that you personally it will give us for you get it will be based rule next will give us false false those plugs points falls through of course this is false do not false so it is true for this will give us force so that force will give us true so therefore not be a restaurant is for you not be or you not you matter equivalent from one another so to more than slow number two the nasty bringing or non use they are logically equivalent based on that demoratized law very closely at denoted by notations upon a subs to the element of theory of element is meaningless in order you might up less it doesn't matter how often the element is fill in a soul definite or class of objects objects insects can see anything or matters these objects are called elements or members of the example the numbers two four five eight and ninety such will usually be denoted by capital letters the elements observed which usually represented by lowercase letters base we are actually importing collections in well defined less demands you know that's the object can be edited can be named the second picks one two three goals with no element you set builder for political study state and property in our elements equals to x such that x isno element add so in this case I know you think elements of j five seven nine suchsuch that text is service to worse and drop as though they are equal so we could say examples of examples for subject mathematical denotions we have the national numbers you will see who actually may zero actual defense by me a negative individual is command that what is a real number the only number are numbers that can be located on the number nine actually anyways a real number is tell you the bridge of numbers that can be located on a number nine specific specific specific number is it can be decimal or you can have fractional rational numbers are national numbers equals to that element of a it is not c is equal to hbasics therefore in general you see is a element of example as the age this is considered as one element such as the art includes in one thirty three and then cxd is another considered one element that they are all enclosed in currently so anybody in an element because they are sweet thank you okay next days we have a is equal to x so let me remote it x element of a okay element xy is not equal to xy element is not equal to another xy element how they are considered as another one power set of x power set in this study is a number of next property nine property and the x triggers b eighty by three or three is a member of the positive numbers for positive numbers and seats you will end up the minister youknew or belongs to it and b belongs to did andgiving an example of having this having this is a property why you know extra process should be zero c zero couple numbers and fuch that are an object x is some a member of set a so a contains x a summat of elements then we write an eta is an element of a or x belongs to a so element representation for example number one for example of a company and they are enclosed for each precious tike is equal to x such that x is x so then one is a member of b correct you are satisfied because a member of yes and four is not a member of so such that x is what describes about anybody she goes to us for this national element to find in two to three courts start to find thousand twenty seconds number four minutes for number five times up the following four you can transfer this one for september if you feel like that you have to rewrite in a regular form or central form you can assist variable x number three national ninety seconds protest equals to rest and thirty four to six equals to one to three four s two point sixgram two point zero in behind my land to zero and x is less than twelve not even less than twelve so two four six eight ten so this equals than for equal to it will become negative two negative one zero one two can be a two here and then mark severe it equals to such and x equal to four and tax to twenty so we have four eight twenty three are equal to x five days of friendswhere you produce that feel ninety four and then picture and message do you any audit solids4. Persist academic warning/flag state and add required Student notification details.
5. Add Administrator Faculty lifecycle management and intrusion-report export, or revise the cases if Registrar ownership is intentional.
