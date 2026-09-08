# PLV BLOCKGO Sample User Manual

**Document type:** Installation, operation, and acceptance-testing guide  
**Target deployment:** Kubernetes local and production profiles  
**Intended readers:** System administrators, registrars, department administrators, faculty, students, testers, and developers

> This is a sample manual for the current repository. Replace organization-specific contacts, screenshots, URLs, and approval signatures before issuing it as the official production manual.

## 1. Purpose and scope

PLV BLOCKGO manages student enrollment and academic grades through a role-based web application. Grades are encoded and reviewed in the application database, then finalized by the Registrar and written to the Hyperledger Fabric ledger. Supporting files are encrypted before being stored in the private IPFS network.

This guide covers:

- workstation and cluster prerequisites;
- secure configuration and Kubernetes installation;
- first login and role-based procedures;
- student ID assignment;
- the faculty-to-department-to-registrar grade workflow;
- ledger and IPFS inspection;
- automated checks and manual acceptance test cases;
- common troubleshooting and safe shutdown.

## 2. Roles and responsibilities

| Role | Main responsibilities | Grade permissions |
|---|---|---|
| System Administrator | Monitor services and manage system-level operations | No academic grade or Fabric-wallet access |
| Registrar | Manage enrollment, assignments, encoding periods, review submitted grades, return records, and finalize records | Review, return, and finalize only; finalized grades are not corrected in the Registrar UI |
| Department Administrator | Review faculty submissions for the department | Approve and forward to the Registrar, or return to Faculty for correction |
| Faculty | Encode raw grades and submit them for review | Create and revise records before approval/finalization |
| Student | View the student's own published records | Read-only access to finalized grades |

### Current feature list

- **System Administrator:** create, update, reset, and remove Registrar accounts; review support tickets; view live transaction activity; inspect Prometheus metrics and scrape targets; open protected Grafana dashboards; and read only structured finalized-grade fields from the Registrar ledger. Wallet databases, MSP data, certificates, CouchDB credentials, raw JSON, and database mutation controls are not exposed.
- **Registrar:** create Faculty and Department Administrator accounts manually or in bulk; enroll Students manually or in bulk; automatically allocate immutable Gregorian-year Student IDs for manual enrollment; create sections and assignments; manage encoding periods; approve curricula; review, return, and finalize Department-approved grades; publish finalized grades to Student accounts; export reports; receive Faculty/Department Administrator password-change requests; and approve or reject those requests.
- **Department Administrator / Chairperson:** create curricula manually or in bulk; manage department sections and Faculty loading; review Faculty submissions; return submissions with a reason; approve and forward valid submissions to the Registrar; and request a password change from inside the authenticated portal.
- **Faculty:** encode raw grades manually or in bulk; use automatic college-grade conversion; set dropped, unofficially dropped, withdrawn, or incomplete statuses; submit grades to the Department Administrator; correct and resubmit returned work; export class records; and request a password change from inside the authenticated portal.
- **Student:** sign in with Student ID only; view personal information from the profile settings card; choose current-semester subjects from a dropdown; view finalized grade and professor details; reveal a subject's blockchain transaction and committing Registrar only on request; view the assigned curriculum; and chat with the Registrar. Students do not participate in the staff password-approval workflow.

The public login screen has no **Forgot Password** action. Password changes for Faculty and Department Administrators use the in-portal Registrar approval workflow; no email OTP, OTP receiver, or SMTP password-reset request is used.

The normal grade lifecycle is:

```text
Faculty encodes raw grade
        |
        v
Faculty submits grade
        |
        v
Department review ---- return ----> Faculty correction and resubmission
        |
      approve
        |
        v
Registrar review ----- return -----> Faculty correction through department workflow
        |
     finalize
        |
        v
Hyperledger Fabric ledger + student view
```

## 3. System requirements

### 3.1 Required software

- Git
- Docker Desktop with Kubernetes enabled, or another Kubernetes v1.24+ cluster
- `kubectl`, configured for the intended cluster
- Bash for deployment scripts (Git Bash or WSL on Windows)
- Node.js 20.x and npm 10+ for frontend and middleware testing
- .NET SDK 8 for backend build verification
- A modern browser such as Edge, Chrome, or Firefox

### 3.2 Suggested local resources

- 4 CPU cores
- 8 GB RAM allocated to the local Kubernetes environment
- Enough free disk space for Docker images and persistent volumes

For production, start with at least 16 GB RAM and size CPU, memory, and storage from measured use. Production storage must use an appropriate CSI-backed storage class instead of workstation host paths.

## 4. Installation

### 4.1 Obtain the source

```bash
git clone <repository-url>
cd Capstone-Project-BlockChain-BlockGo-Backup-2
```

If the source is already present, confirm the intended branch and working tree before deploying:

```bash
git branch --show-current
git status --short
```

Do not discard local changes unless they have been reviewed and backed up.

### 4.2 Check Kubernetes

```bash
docker version
kubectl version --client
kubectl cluster-info
kubectl get nodes
```

At least one node must report `Ready`. On Docker Desktop, enable Kubernetes and wait for it to finish starting before continuing.

### 4.3 Configure secrets

Create or update `network/.env`. Use unique, randomly generated values and never commit the file. The following is a template; every value in angle brackets must be replaced:

```dotenv
# Application security
JWT_SECRET=<long-random-jwt-secret>
INTERNAL_API_KEY=<long-random-internal-api-key>
IPFS_ENCRYPTION_KEY=<long-random-ipfs-encryption-key>
VAULT_PASSWORD=<strong-vault-password>

# Bootstrap accounts
BOOTSTRAP_REGISTRAR_EMAIL=registrar@plv.edu.ph
BOOTSTRAP_REGISTRAR_PASS=<strong-registrar-password>
BOOTSTRAP_SYSTEM_ADMIN_EMAIL=system-admin@plv.edu.ph
BOOTSTRAP_SYSTEM_ADMIN_PASS=<strong-system-admin-password>

# Fabric CA enrollment secrets
FABRIC_CA_REGISTRAR_PASS=<strong-ca-registrar-secret>
FABRIC_CA_FACULTY_PASS=<strong-ca-faculty-secret>
FABRIC_CA_DEPARTMENT_PASS=<strong-ca-department-secret>

# PostgreSQL
POSTGRES_USER=<database-user>
POSTGRES_PASS=<strong-database-password>
POSTGRES_DB=ActivityLogs
POSTGRES_REPL_USER=<replication-user>
POSTGRES_REPL_PASS=<strong-replication-password>

# CouchDB
COUCHDB_USER=<couchdb-administrator>
COUCHDB_PASS=<strong-couchdb-password>
```

Important security notes:

- The bootstrap job creates an account only when it does not already exist. Changing a bootstrap password in `.env` does not rotate the password of an existing account.
- Do not print, screenshot, or include real passwords in this manual or in test evidence.
- Production deployments require non-placeholder PostgreSQL, replication, and CouchDB passwords.
- Use a managed secret store for production when available.

### 4.4 Pre-deployment validation

Run the following from Git Bash or WSL:

```bash
cd network
chmod +x ./k8s/deploy-k8s.sh
./k8s/deploy-k8s.sh local verify
```

The verification command checks required inputs and deployment prerequisites without performing a full deployment.

### 4.5 Deploy locally

From the `network` directory:

```bash
./k8s/deploy-k8s.sh local apply
```

The local deployment rebuilds the frontend, middleware, shared .NET backend, and chaincode images from the current workspace. It deploys both application backends as microservices, applies Kubernetes resources, initializes the Fabric channel and chaincodes, and starts localhost port-forwards. One shared image is used by each backend family, while Kubernetes starts a separate process and Deployment for every service role.

Wait for the command to complete. Then open:

```text
http://localhost:8080
```

### 4.6 Deploy to production

Before a production deployment:

1. Build and publish the images from the reviewed source revision.
2. Set the production image repository and immutable image tag expected by the manifests.
3. Verify production secrets and storage classes.
4. Confirm that the Kubernetes context points to the production cluster.
5. Schedule a deployment window and prepare a rollback plan.

Then run from `network`:

```bash
./k8s/deploy-k8s.sh production verify
./k8s/deploy-k8s.sh production apply
./k8s/deploy-k8s.sh production status
```

Do not expose CouchDB, PostgreSQL, Fabric peers/orderers, or the IPFS administration API directly to the public internet.

## 5. Deployment verification

### 5.1 Check application status

```bash
cd network
./k8s/deploy-k8s.sh local status
```

Inspect all namespaces:

```bash
kubectl get pods -n plv-fabric
kubectl get pods -n plv-main-campus
kubectl get pods -n plv-annex-campus
kubectl get pods -n plv-pubad-campus
kubectl get pvc --all-namespaces
```

Application pods should be `Running` and ready. Completed bootstrap jobs may show `Completed`, which is expected.

The .NET backend should contain these Deployments: `dotnet-api-gateway`, `dotnet-auth-service`, `dotnet-academic-service`, `dotnet-grade-service`, `dotnet-operations-service`, and `dotnet-realtime-service`. The Node.js middleware should contain its gateway and auth, identity, ledger, upload, and settings services. Check them directly with:

```bash
kubectl get deployment -n plv-fabric
```

### 5.2 Check health endpoints

With the local frontend port-forward active:

```bash
curl http://localhost:8080/nginx-health
curl http://localhost:8080/api/backend/health
```

For direct middleware diagnostics, start a temporary terminal session:

```bash
kubectl port-forward -n plv-fabric svc/middleware-api 4000:4000
```

In another terminal:

```bash
curl http://localhost:4000/api/health
curl http://localhost:4000/api/ready
```

For direct .NET microservice diagnostics, start another temporary terminal session:

```bash
kubectl port-forward -n plv-fabric svc/dotnet-api-gateway 5000:5000
```

Then run:

```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/ready
```

Each gateway readiness response should show its internal services as available. The normal frontend routes remain unchanged because `client-app-service:5000` is retained as a compatibility address for the .NET gateway.

### 5.3 Local administration endpoints

| Purpose | Local address | Notes |
|---|---|---|
| Web application | `http://localhost:8080` | Main user entry point |
| Private IPFS Web UI | `http://localhost:8080/ipfs-webui/` | Trusted administrators only |
| Finalized grade ledger | System Administration -> **Infrastructure & Data** | Structured read-only records; no raw JSON or credentials |
| Prometheus | System Administration -> **Prometheus Live** | Protected live metrics; refreshes every five seconds |
| Grafana | System Administration -> **Grafana Observability** | Protected same-origin proxy |

Direct CouchDB and Prometheus ports are intentionally unavailable to browsers. Addresses `localhost:5986`, `localhost:5990`, `localhost:6990`, `localhost:7990`, and `localhost:9090` must remain closed. The application backend connects to the internal `ClusterIP` services and enforces the System Administrator role.

## 6. How to use the role tutorials

The following chapters are independent. A user should follow only the chapter for the role assigned to that account:

1. **System Administrator** — monitoring, Registrar accounts, alerts, and support tickets.
2. **Registrar** — enrollment, staff accounts, assignments, encoding schedules, grade review, and finalization.
3. **Department Administrator / Chairperson** — department setup, Faculty assignment, curriculum preparation, and grade review.
4. **Faculty** — manual or bulk grade encoding, correction, and submission.
5. **Student** — viewing finalized grades, curriculum, and blockchain transactions.

Each tutorial uses this format:

- **Before you begin** lists prerequisites.
- **Steps** gives the actions in the order they must be performed.
- **Expected result** tells the user how to confirm completion.

For every role, begin by opening `http://localhost:8080`. Enter only the account issued to that person. Never share accounts because the system records actions against the signed-in identity.

## 7. System Administrator tutorial

The System Administrator portal is for infrastructure oversight and Registrar account administration. This role is database-only and must not be used to inspect or change academic grades.

### 7.1 Sign in and verify the portal

**Before you begin:** The account has been provisioned using `BOOTSTRAP_SYSTEM_ADMIN_EMAIL` and its original password.

**Steps:**

1. Open `http://localhost:8080`.
2. Enter the configured System Administrator email.
3. Enter the account password.
4. Select **Login**.
5. Wait for the **System Administration** portal to load.
6. Confirm that the left navigation contains **Overview**, **Registrar Accounts**, **Error Reports**, **Live Transactions**, **Infrastructure & Data**, **Prometheus Live**, **Alerts**, and **Grafana Observability**.

**Expected result:** The System Administration portal opens. Registrar, Faculty, Department, and Student academic screens are not available.

### 7.2 Review the system overview

**Steps:**

1. Select **Overview**.
2. Review the service health cards.
3. Check the number of open, recent, and resolved error reports.
4. Select **View Error Reports** if an item needs attention.
5. Refresh the browser only if a card is stale; do not repeatedly refresh during a known restart.

**Expected result:** Current service and support summaries are visible without exposing academic records.

### 7.3 Check infrastructure and data services

**Steps:**

1. Select **Infrastructure & Data**.
2. Review frontend, middleware, backend, PostgreSQL, Fabric, CouchDB, and IPFS indicators displayed by the portal.
3. In **Finalized Grade Ledger**, review only the structured finalized-grade columns such as Student, Subject, Grade, class, Faculty, finalized time, and transaction ID.
4. Confirm that no database selector, wallet database, MSP material, certificate, credential, raw JSON, edit, or delete control is present.
5. Note the name and status of any unhealthy component.
6. Cross-check an unhealthy component using the commands in Section 16.
7. Record the timestamp and non-sensitive error details in an incident ticket.

**Expected result:** Healthy components report an available/healthy state. Only finalized Registrar grades are readable, and the view cannot alter CouchDB data.

### 7.4 Review alerts

**Steps:**

1. Select **Alerts**.
2. Read active alerts from highest to lowest severity.
3. Open the related infrastructure view or logs.
4. Record the alert time, affected component, and current status.
5. Escalate the incident according to the organization's support procedure.

**Expected result:** Every active alert has an owner or escalation record. Reviewing an alert does not alter academic data.

### 7.5 Use Prometheus Live and Grafana observability

**Before you begin:** The containerized Prometheus and Grafana pods must be Ready. Both services remain internal and are accessed through the authenticated System Administrator portal.

**Steps:**

1. Select **Prometheus Live**.
2. Verify the pulsing **LIVE** indicator and the last-update time.
3. Review CPU, memory, running pods, healthy targets, and down targets.
4. Inspect any down target and its last scrape error. The page refreshes every five seconds and also has a manual **Refresh** action.
5. Select **Grafana Observability**.
6. Choose the relevant dashboard or service and set a time range that includes the reported incident.
7. Review request rate, errors, latency, CPU, and memory.
8. Save or screenshot only non-sensitive graphs for the incident record.

**Expected result:** Prometheus displays live values and active scrape targets without opening port 9090. Grafana loads through the protected application proxy.

### 7.6 Create a Registrar account

**Before you begin:** Confirm that fewer than two active Registrar accounts exist and that creating another account is authorized.

**Steps:**

1. Select **Registrar Accounts**.
2. Review the account counter. The portal permits at most two current Registrar accounts.
3. In **Create Registrar Account**, enter the authorized Registrar's full name, institutional email, and temporary password.
4. Recheck the email address before saving.
5. Select **Create Registrar**.
6. Give the temporary credential to the Registrar through an approved secure channel.
7. Ask the Registrar to test the account and change the temporary password according to policy.

**Expected result:** A success notice appears, the account is listed under **Registrar Access**, and the account counter increases by one.

### 7.7 Update a Registrar email or reset its password

**Steps:**

1. Select **Registrar Accounts**.
2. Locate the intended Registrar under **Registrar Access**.
3. To change email, enter **New Email** and select **Update Email**.
4. To reset a password, enter **New Password** and **Confirm Password**.
5. Verify that both password values match and contain at least eight characters.
6. Select **Reset Password**.
7. Send the updated credential through an approved secure channel.

**Expected result:** The portal shows a successful update. Other Registrar accounts remain unchanged.

### 7.8 Delete a Registrar account

**Before you begin:** Confirm the request is authorized and that deleting the account will not remove the last required operational Registrar.

**Steps:**

1. Select **Registrar Accounts**.
2. Locate the exact account by name, email, and account ID.
3. Select **Delete Registrar**.
4. Read the confirmation message carefully.
5. Confirm only if the displayed account is the intended target.
6. Refresh the list.

**Expected result:** The selected account is removed and one Registrar slot becomes available. Other accounts are unaffected.

### 7.9 Process a Registrar error report

**Steps:**

1. Select **Error Reports**.
2. Select **Refresh** to load current tickets.
3. Locate the ticket by ID and title.
4. Read the description, severity, Registrar name, and current assignment.
5. Select one of the approved support specialists.
6. Change the status from **Open** to **In Progress** when work begins.
7. Enter or update the resolution notes.
8. Select **Save**.
9. After verification, change the status to **Resolved** or **Closed** and select **Save** again.
10. If all users must be informed, enter a short non-sensitive message under **Broadcast Resolution Notice** and select **Broadcast Notice**.

**Expected result:** The ticket displays the assigned specialist, saved notes, and correct status. Any broadcast appears as a system notice to logged-in users.

### 7.10 Sign out

1. Finish or save the current task.
2. Select **Logout** in the portal header.
3. Confirm that the login page appears.
4. Close the browser on a shared workstation.

## 8. Registrar tutorial

The Registrar performs institution-wide enrollment and finalization tasks. The Registrar reviews academic values but does not directly correct them.

### 8.1 Sign in and verify the Registrar portal

**Before you begin:** Use the Registrar email and the password originally provisioned for that account.

**Steps:**

1. Open `http://localhost:8080`.
2. Enter the Registrar email and password.
3. Select **Login**.
4. Wait for the **Registrar Portal** to load.
5. Confirm the sidebar contains **Dashboard**, **Encoding Period**, **Enrollment Management**, **Operations**, **Grade Finalization**, and **Reports & PDF**.
6. Expand **Enrollment Management** and **Operations** to see their submenus.

**Expected result:** The Registrar dashboard opens and Registrar-only controls are visible.

### 8.2 Review the dashboard

**Steps:**

1. Select **Dashboard**.
2. Review submitted, approved, returned, and finalized record counts.
3. Check Faculty encoding activity and any priority statuses.
4. Use the dashboard only as a summary; open the relevant detailed screen before taking action.

**Expected result:** Current workflow totals are displayed and can be traced to detailed records.

### 8.3 Configure the encoding period

**Before you begin:** Confirm the approved semester, grading term, opening date, and closing date.

**Steps:**

1. Select **Encoding Period**.
2. Under **Encoding Period Control**, choose **1st Semester**, **2nd Semester**, or **Summer**.
3. Choose **Midterms** or **Finals** under **Encoding Term**.
4. Select the **Start Date**.
5. Select the **End Date**. It must not be earlier than the start date.
6. Recheck the semester, term, and dates.
7. Select **Save Schedule**.
8. Review **Current Schedule** and confirm that the saved values are correct.
9. Ask a Faculty test user to confirm that encoding is enabled only inside the schedule.

**Expected result:** A success message appears, the schedule is shown under **Current Schedule**, and Faculty receives the correct open, not-started, urgent, or closed banner.

The system uses Gregorian calendar years. A valid leap date such as February 29, 2028 must save without crashing and must not affect student ID generation.

> **Caution:** **Reset Encoding Season** is a separate administrative action. Use it only at the approved end of a grading cycle because it clears cycle-specific working state.

### 8.4 Create a Faculty or Department Administrator account

**Before you begin:** Obtain an approved institutional ID, official name, email, role, program, and temporary password.

**Steps:**

1. Expand **Operations**.
2. Select **Create Staff Accounts**.
3. Under **Account Details**, choose **Faculty** or **Chairperson / Department Head**.
4. Enter the **Institutional ID** and official email.
5. Under **Personal Information**, enter first, middle, and last name. Middle name is optional.
6. Under **Academic Assignment**, select the academic program.
7. For Faculty, select **Regular**, **Part-time**, or **Full-time** as applicable.
8. Enter a temporary password containing at least eight characters.
9. Review all values.
10. Select **Create Account**.
11. Deliver the temporary credential through an approved secure channel.

**Expected result:** A success notice identifies the created account. A program cannot receive a second active Chairperson when the one-Chairperson limit applies.

For multiple Faculty accounts, select **Bulk Upload**, download the staff template, complete one account per row, and upload the CSV or XLSX file. The result identifies the batch and reports each rejected row; successfully created accounts are not repeated when failed rows are corrected.

### 8.5 Enroll one student manually

**Before you begin:** Have the student's approved personal information, academic program, school year, year level, and curriculum version.

**Steps:**

1. Expand **Enrollment Management**.
2. Select **Student Enrollment**.
3. Under **Enrollment Setup**, select the **Academic Program**.
4. Enter the **School Year**, such as `2026-2027`.
5. Select the **Year Level**.
6. Select a published **Curriculum Version**, or leave **Latest published version (automatic)** when appropriate.
7. Under **Enrollment Method**, select **Manual Entry**.
8. Enter first name, last name, optional middle name, birthdate, email, contact number, and home address.
9. If a Student ID field is displayed, confirm that it is read-only. Do not attempt to type over it.
10. Recheck the student's name, birthdate, email, program, and school year.
11. Select **Save Student**.
12. Find the student in **Current Student Enrollments** and note the generated Student ID.

**Expected result:** The student is saved once and receives the next automatic ID for the starting Gregorian year of the school year.

Automatic Student ID rules:

- Format: `YY-NNNN`.
- `YY` is the last two digits of the Gregorian enrollment year.
- `NNNN` runs from `0001` to `9999` independently for each year.
- In an empty 2026 sequence, the first generated ID is `26-0001`; the next is `26-0002`.
- In an empty 2027 sequence, the first generated ID is `27-0001`.
- Changing the current year never changes an existing student's ID.
- When `YY-9999` exists, the system must reject another automatic ID for that year with a clear capacity message.

### 8.6 Enroll students through bulk upload

**Before you begin:** Use a copy of the current template and a test batch before importing a large official list.

**Steps:**

1. Expand **Enrollment Management** and select **Student Enrollment**.
2. Select the academic program, school year, year level, and curriculum version under **Enrollment Setup**.
3. Select **Bulk Upload** under **Enrollment Method**.
4. Select **Download Template**.
5. Open the template and keep its header names and order unchanged.
6. Enter one student per row and complete all required columns.
7. Leave Student ID blank to generate the next ID for the selected Gregorian school-year start, or enter an approved Student ID when the Registrar must preserve IDs supplied by an official bulk list.
8. Check duplicate emails, duplicate IDs, invalid dates, and blank required cells.
9. Save as `.xlsx` or `.csv`.
10. Drag the file into the upload area or select it using the file browser.
11. Confirm that the correct filename is displayed.
12. Select **Upload & Enroll**.
13. Review the successful and failed row counts.
14. Correct only the failed rows and upload those corrected rows again.
15. Search **Current Student Enrollments** to confirm the imported students.

**Expected result:** Valid students are enrolled once. A Student ID explicitly supplied in the supported bulk template is preserved; it is not replaced by automatic generation. Duplicate or malformed values are reported rather than silently changed.

### 8.7 Create and review department sections

**Steps:**

1. Expand **Enrollment Management**.
2. Select **Department Sections**.
3. Choose the program, school year, semester, and year level.
4. Enter or select the section identifier and required capacity information.
5. Review the planned student grouping.
6. Save or create the section.
7. Select **Sections Created**.
8. Search for the new section and verify its program, year level, semester, and roster.

**Expected result:** The new section is listed under **Sections Created** and is available for assignment.

### 8.8 Assign students, Chairpersons, and Faculty

**Steps:**

1. Expand **Operations**.
2. Select **Assigning**.
3. Choose the relevant assignment tab: students, Chairpersons, or Faculty.
4. For a student, select department, year level, and section, then select **Assign**.
5. For a Chairperson, select the authorized department, then select **Assign**.
6. For Faculty, select department, section, year level, and subject code, then select **Assign**.
7. Refresh the list.
8. Confirm that the displayed current assignment matches the intended values.
9. Ask the assigned Faculty or Chairperson to sign in and verify the assignment.

**Expected result:** Each account receives only the selected academic scope. No unrelated assignment is changed.

### 8.9 Review and publish a curriculum

**Steps:**

1. Expand **Enrollment Management**.
2. Select **Curriculum Management**.
3. Select **Pending Approval**.
4. Choose a curriculum version from the left panel.
5. Review program code, version, subject codes, titles, units, prerequisites, and total units.
6. If changes are needed, select **Return for Revision** and enter a clear comment.
7. If correct, select **Approve**.
8. Open the **Approved** tab and select the same version.
9. Select **Publish** when it is ready for enrollment use.
10. Confirm that it appears under **Published**.

**Expected result:** Returned curricula go back for revision. Published curricula become available for student enrollment and assignment.

### 8.10 Review the Grades Ledger

**Steps:**

1. Expand **Operations**.
2. Select **Grades Ledger**.
3. Select a Faculty member in **Faculty Encoding Monitoring**.
4. Expand the required section using **View Grades**.
5. Filter by department, year level, or section when necessary.
6. Compare student name, subject, midterm/finals values, calculated final rating, student status, record status, and flags.
7. Confirm that the record came through Department approval.
8. If **View File** is shown, follow Section 8.11.
9. If **No File** is shown, verify whether the record has an `ipfs_cid` before reporting a defect.
10. Do not attempt to change a grade value.

**Expected result:** The Registrar can review the record and its evidence. No **Correct Grade** action is displayed, including for the genesis record.

### 8.11 View an attached grade file

**Before you begin:** The record must show **View File**, and the authorized operator must know the vault password through a secure channel.

**Steps:**

1. Select **View File** for the intended non-genesis record.
2. Confirm that the displayed record and CID are the intended ones.
3. Enter the vault password in the prompt.
4. Select **Decrypt & View**.
5. Verify that the decrypted file belongs to the selected section and term.
6. Close the file after review.

**Expected result:** Authorized decryption opens the correct file. A record without `ipfs_cid` continues to show **No File** and is not changed.

### 8.12 Return a grade for correction

**Before you begin:** The record must not be finalized. Document the exact issue found during review.

**Steps:**

1. Open the pending grade from **Grades Ledger** or **Grade Finalization**.
2. Verify the student, subject, term, and Department approval status.
3. Select **Return** when that action is available for the pending record.
4. Enter a specific correction reason; do not enter only “wrong grade.”
5. Confirm the return.
6. Verify that the record leaves the finalization queue or displays a returned status.
7. Notify the Department/Faculty through the system workflow if needed.

**Expected result:** The record is returned for Faculty correction and is not written as a finalized grade. The Registrar does not edit the value.

### 8.13 Finalize approved grades to the ledger

**Before you begin:** The Department Administrator has approved and forwarded the records. Review all exceptional student statuses and evidence first.

**Steps:**

1. Select **Grade Finalization**.
2. Select **Refresh Staging**.
3. Find the intended group under **Grades Pending Ledger Entry**.
4. Verify department, Faculty, section, subject, school year, semester, and term.
5. Review every student row in the group.
6. Confirm that all displayed equivalents match the raw grades.
7. Confirm that return reasons and unresolved flags are absent.
8. Select **Finalize All to Ledger**.
9. Read the confirmation dialog.
10. Confirm the action once.
11. Wait for the success response; do not double-click or refresh during submission.
12. Record the ledger transaction or audit reference.
13. Refresh the queue and confirm that the group is no longer pending.
14. Verify the non-genesis record in CouchDB using Section 12.2.

**Expected result:** Records become finalized, appear in the Fabric world state and authorized Student view, and cannot be corrected through the Registrar portal.

### 8.14 Export reports and PDFs

**Steps:**

1. Select **Reports & PDF**, or use the export action on the current Registrar screen.
2. Set the department, school year, semester, year level, and section filters.
3. Review the preview and totals.
4. Select **Export PDF** or **Export Summary for Signing**.
5. Open the downloaded file.
6. Verify the title, filters, page count, students, grades, and signature area.
7. Store the report only in an approved location.

**Expected result:** The report contains only the selected scope and matches the portal data.

### 8.15 Review password-change requests

**Steps:**

1. Expand **Operations** and select **Password Management**.
2. Review the pending requests. Each item identifies the Faculty or Department Administrator account, request time, and optional reason.
3. Select the exact request and verify the requester identity.
4. Select **Approve** to allow the requester to set a new password, or select **Reject** when the request is not authorized.
5. When rejecting, enter the required review note so the requester understands the decision.
6. Confirm the decision and wait for the status to update.
7. Do not ask for, enter, receive, or send the requester's new password.

**Expected result:** The requester receives the decision in the authenticated portal. An approved requester sets the new password personally. No email OTP, OTP receiver, SMTP password-reset message, or Registrar-known temporary password is involved.

### 8.16 Revoke an account

**Before you begin:** Obtain authorization and confirm that reassignment or grade-work handoff is complete.

**Steps:**

1. Expand **Operations** and select **Account Revocation**.
2. Choose the Chairperson or Faculty group.
3. Search for the account by name and email.
4. Review its current department and assignment.
5. Select the revoke action.
6. Read the confirmation dialog and verify the target again.
7. Confirm the revocation.
8. Refresh the account list.

**Expected result:** The selected account loses access. Other accounts and finalized ledger records remain unchanged.

### 8.17 Report a system error

**Steps:**

1. Expand **Operations** and select **Report System Error**.
2. Enter a short, specific title.
3. Select the severity that matches the impact.
4. Describe what you were doing, what happened, and what was expected.
5. Include the time, affected screen, and non-sensitive record ID.
6. Do not include passwords, vault secrets, tokens, or unnecessary student data.
7. Submit the report.
8. Record the ticket ID.

**Expected result:** A support ticket is created and becomes visible to the System Administrator.

### 8.18 Sign out

1. Complete or cancel any open form.
2. Select **Logout**.
3. Confirm that the login page appears.
4. Close the browser on a shared workstation.

## 9. Department Administrator / Chairperson tutorial

The Department Administrator, shown as **Chairperson** in parts of the interface, manages only the assigned academic department. This role reviews Faculty submissions before they reach the Registrar.

### 9.1 Sign in and verify the department scope

**Steps:**

1. Open `http://localhost:8080`.
2. Enter the Department Administrator email and password.
3. Select **Login**.
4. Confirm that the header shows the correct name and department.
5. Confirm that the menu contains **Encoding Monitoring**, **Department Sections**, **Academic Assignment**, **Curriculum Builder**, and **For Review**.

**Expected result:** The Chairperson portal opens and displays only the assigned department's Faculty and sections.

### 9.2 Monitor Faculty encoding

**Steps:**

1. Select **Encoding Monitoring**.
2. Review total Faculty, section progress, submitted records, special student statuses, and flags.
3. Select a Faculty or section that needs attention.
4. Check whether the active term is Midterms or Finals.
5. Contact the Faculty through the approved communication channel when a deadline or incomplete section needs attention.

**Expected result:** The department's current encoding progress is visible without changing grades.

### 9.3 Create or manage department sections

**Steps:**

1. Select **Department Sections**.
2. Select the school year, semester, year level, and program information available to the department.
3. Create or select the intended section.
4. Review the section roster and capacity.
5. Add or move students only through the controls authorized for the department.
6. Save the changes.
7. Reopen the section to confirm the saved roster.

**Expected result:** The section contains the intended students and remains limited to the Chairperson's department.

### 9.4 Assign Faculty academically

**Steps:**

1. Select **Academic Assignment**.
2. Choose the section and subject.
3. Select an available Faculty member from the same department.
4. Review school year, semester, schedule, and load information.
5. Select the assignment action.
6. Confirm the assignment.
7. Ask the Faculty member to verify that the section appears in the Faculty portal.

**Expected result:** The chosen Faculty member receives the intended section and subject only.

### 9.5 Build and submit a curriculum

**Steps:**

1. Select **Curriculum Builder**.
2. Create a new curriculum version or open a returned draft.
3. Enter the curriculum name, version, and applicable academic year.
4. Add each subject code, title, units, year level, semester, and prerequisites.
5. Check total units and prerequisite order.
6. Save the draft.
7. Review all years and semesters in the curriculum viewer.
8. Select **Submit for Approval**.
9. If the Registrar returns it, read the comment, revise the affected items, and submit again.

**Expected result:** The curriculum enters the Registrar's pending-approval list and cannot be used as published curriculum until approved and published.

### 9.6 Open a Faculty submission for review

**Before you begin:** Faculty must have selected **Submit to Chairperson** for the active term.

**Steps:**

1. Select **For Review**.
2. Find the Faculty and section marked submitted or pending review.
3. Select the section row.
4. Review the **Submitted Grades** panel.
5. Confirm student IDs, student names, subject, active term, raw values, final grades, equivalents, student statuses, and flags.
6. If **View File** is shown, open it using the authorized vault procedure.
7. Check every row before choosing a section-level action.

**Expected result:** The selected section's complete submitted roster is displayed for review.

### 9.7 Return a section to Faculty

**Steps:**

1. Keep the intended section open under **For Review**.
2. Identify every row or value requiring correction.
3. Enter a clear note describing the problem and expected correction.
4. Select **Send Back** or the displayed return action.
5. Confirm the return.
6. Verify that the section status changes to returned.
7. Confirm with the Faculty user that the note is visible and editing is available again.

**Expected result:** The section returns to Faculty with the reason. It is not forwarded to the Registrar and is not finalized.

### 9.8 Approve and forward a section to the Registrar

**Steps:**

1. Open the submitted section under **For Review**.
2. Review every student row and any supporting file.
3. Enter an optional review note when useful.
4. Select **Approve Section**.
5. Confirm that the section status becomes approved.
6. Select **Submit to Registrar**.
7. Confirm the forwarding action.
8. Verify that the status becomes forwarded/submitted to Registrar.
9. Confirm that the section no longer appears as an unreviewed submission.

**Expected result:** The approved section appears in the Registrar's pending finalization workflow. Students still cannot see it as finalized.

### 9.9 Request and complete a password change

**Steps:**

1. While signed in, select **Request Password Change** in the portal header.
2. Enter an optional reason and select **Send Request to Registrar**.
3. Wait for the status to change from **Pending**. The portal checks for a Registrar decision automatically.
4. If rejected, read the Registrar note and submit a new request only after resolving the issue.
5. If approved, enter and confirm a strong new password in the same dialog.
6. Select **Change Password**, then use the new password at the next login.

**Expected result:** The password changes only after Registrar approval. No OTP or email code is requested or sent.

### 9.10 Sign out

1. Finish or cancel the current review.
2. Select **Logout**.
3. Confirm that the login page appears.

## 10. Faculty tutorial

Faculty encodes raw numeric grades. The application calculates the final grade and college equivalent automatically.

### 10.1 Sign in and check the encoding period

**Steps:**

1. Open `http://localhost:8080`.
2. Enter the Faculty email and password.
3. Select **Login**.
4. Read the encoding-period banner before opening a class.
5. Confirm the semester and whether the active term is Midterms or Finals.
6. If the banner says not set, not started, or closed, do not attempt to bypass it; contact the Registrar.

**Expected result:** The Faculty portal opens. Encoding controls are available only when the approved schedule is open.

### 10.2 Open an assigned section

**Steps:**

1. Select the correct year-level tab or **All Sections**.
2. Use **Search for a section** if needed.
3. Review the section card's subject, roster count, progress, and review status.
4. Select the intended section card.
5. Verify the section name and student roster before entering data.

**Expected result:** The grade table opens for the intended assigned section and active term.

### 10.3 Encode grades manually

**Before you begin:** Use official source records and confirm that the correct term is active.

**Steps:**

1. Locate the student by Student ID and name.
2. For Midterms, enter the raw value in **Midterm**. For Finals, enter the raw value in **Finals**.
3. Enter only values allowed by the form, normally 60 through 100.
4. Move to the next row and continue until all active students are encoded.
5. Review **Final Grade**, **Grade Equivalent**, and **Status** calculated by the system.
6. Correct any red validation message before saving.
7. Select **Save Draft**.
8. Wait for the saved confirmation.

**Expected result:** Raw grades are saved as a draft, calculated fields update automatically, and the section remains editable until submission.

The current college-equivalent scale is:

| Raw grade | Equivalent |
|---|---:|
| 98.5 and above | 1.00 |
| 94.0 to below 98.5 | 1.25 |
| 91.0 to below 94.0 | 1.50 |
| 88.0 to below 91.0 | 1.75 |
| 84.0 to below 88.0 | 2.00 |
| 81.0 to below 84.0 | 2.25 |
| 78.0 to below 81.0 | 2.50 |
| 75.0 to below 78.0 | 3.00 |
| Below 75.0 | 5.00 |

Faculty must not type the college equivalent manually. The system converts the applicable raw grade or calculated final average.

### 10.4 Set a special student status or flag

**Steps:**

1. Locate the intended student row.
2. Open **Student Status**.
3. Choose **Active**, **Dropped (D)**, **Unofficial Dropped (UD)**, **Withdrawn (W)**, or **Incomplete (INC)** based on authorized records.
4. Select **Flag** when the row requires reviewer attention.
5. Select **Save Draft**.
6. Reopen or refresh the section and confirm the status and flag.

**Expected result:** The chosen status is saved and highlighted for Department and Registrar review. A non-active student row is protected from ordinary grade encoding where required.

### 10.5 Upload grades in bulk

**Before you begin:** Use the template produced for the exact section and active term.

**Steps:**

1. Open the assigned section.
2. Select **Grading Sheet Template**.
3. Open the downloaded file without changing its headers or student identifiers.
4. Enter the raw grade for each student in the active-term column.
5. Validate that every grade is inside the permitted range.
6. Save the file as `.xlsx` or `.csv`.
7. Select **Bulk Upload**.
8. Choose the completed file.
9. Review the upload summary, successful rows, and failed rows.
10. Correct and re-upload the sheet if validation fails.
11. Review the calculated final grades and equivalents in the portal.

**Expected result:** Valid grades are loaded for the correct students. Manual cells become locked for a bulk-uploaded section; corrections are made by uploading an updated sheet before submission.

### 10.6 Submit grades to the Chairperson

**Before you begin:** All required students must have valid values or an authorized special status. Resolve validation errors and review the entire section.

**Steps:**

1. Open the intended section.
2. Compare the portal values with the official source record.
3. Confirm the active term, section, and subject.
4. Select **Save Draft** one final time.
5. Select **Submit to Chairperson**.
6. Read the **Submit Grades to Chairperson** confirmation.
7. Select **Yes, Submit Final Grades** only when the section is complete.
8. Wait for the submitted status.

**Expected result:** The section status becomes **Submitted**, editing is locked, and the section appears in the Chairperson's review queue.

### 10.7 Correct a returned section

**Steps:**

1. Open the section marked **Returned**.
2. Read the **Returned by chairperson** note completely.
3. Compare the requested correction with the official source record.
4. Correct only the affected raw grade, status, flag, or file.
5. Review the automatically recalculated final grade and equivalent.
6. Select **Save Draft**.
7. Review the complete section again.
8. Select **Submit to Chairperson**.
9. Confirm resubmission.

**Expected result:** The corrected section returns to the Chairperson review queue. Previously finalized grades are not edited by this process.

### 10.8 Export submitted grades

**Steps:**

1. Open a section already submitted to the Chairperson.
2. Select **Export PDF**.
3. Open the downloaded report.
4. Check section, subject, term, students, grades, statuses, and page count.
5. Store or send the report only through an approved channel.

**Expected result:** The PDF matches the locked submitted section.

### 10.9 View the program curriculum

**Steps:**

1. Select **View Program Curriculum**.
2. Review the published curriculum and subject sequence.
3. Confirm that the encoded subject belongs to the intended program and term.
4. Select **Back to Grade Encoding**.

**Expected result:** The published curriculum is read-only and the Faculty returns to the previous grading workflow.

### 10.10 Request and complete a password change

**Steps:**

1. While signed in, select **Request Password Change** in the portal header.
2. Enter an optional reason and select **Send Request to Registrar**.
3. Wait for the status to change from **Pending**. The portal checks for a Registrar decision automatically.
4. If rejected, read the Registrar note and submit a new request only after resolving the issue.
5. If approved, enter and confirm a strong new password in the same dialog.
6. Select **Change Password**, then use the new password at the next login.

**Expected result:** The password changes only after Registrar approval. No OTP or email code is requested or sent.

### 10.11 Sign out

1. Save any permitted draft work.
2. Select **Logout**.
3. Confirm that the login page appears.

## 11. Student tutorial

The Student portal is read-only. It displays the signed-in student's own finalized academic records.

### 11.1 Sign in and verify personal information

**Steps:**

1. Open `http://localhost:8080`.
2. Enter the assigned Student ID (for example, `26-0001`) and password. Student email addresses are not accepted as login identifiers.
3. Select **Login**.
4. Review the personal-information card.
5. Confirm Student ID, name, program, section, year level, school year, semester, and enrollment status.
6. Report incorrect profile information to the Registrar; do not use another student's account.

**Expected result:** The Student portal opens and displays only the signed-in student's profile.

### 11.2 View finalized grades

**Steps:**

1. Select **My Grades**.
2. Open the current-semester subject dropdown.
3. Select the intended subject.
4. Review its grade, equivalent, professor, and the Registrar identity that committed the finalized record.
5. Review the summary values for total units, GWA, failed subjects, and Dean's List status where applicable.
6. If an expected grade is absent, confirm with Faculty or the Department whether Registrar finalization is complete.

**Expected result:** Only finalized, read-only records belonging to the signed-in student appear. Pending, returned, approved, or merely forwarded records do not appear as finalized grades.

### 11.3 View the curriculum checklist

**Steps:**

1. Select **Curriculum Checklist**.
2. Wait for the assigned published curriculum to load.
3. Review subjects by year level and semester.
4. Check subject codes, titles, units, and prerequisites.
5. Contact the Registrar if the curriculum is missing or does not match the student's program/version.

**Expected result:** The student's assigned published curriculum is displayed read-only.

### 11.4 View a subject's blockchain transaction

**Steps:**

1. Select **My Grades**, then choose the intended current-semester subject.
2. Select **View my blockchain transaction**.
3. Review its transaction identifier, record identifier, timestamp, status, and committing Registrar.
4. Select **Hide my blockchain transaction** when finished.
5. Do not share the screen if it exposes personal academic information.

**Expected result:** The transaction information corresponds to the student's finalized grade records.

### 11.5 Handle an empty or unavailable grade list

**Steps:**

1. Confirm that the correct Student account is signed in.
2. Select **My Grades** and check the current-semester subject dropdown.
3. Refresh once.
4. If the page says there are no records, ask whether the Registrar has finalized the grade.
5. If an error says records cannot be retrieved, note the time and report it to support or the Registrar.
6. Do not repeatedly submit login attempts or use another student's credentials.

**Expected result:** An empty list is treated as a workflow question; a retrieval error is treated as a technical issue. No data is changed.

### 11.6 Sign out

1. Select **Logout**.
2. Confirm that the login page appears.
3. Close the browser on a shared device.

## 12. Files, IPFS, and ledger inspection

### 12.1 Meaning of View File and No File

- **View File** is shown only when the grade record has a valid `ipfs_cid`.
- **No File** is correct when no supporting file was uploaded for that record.
- Final-term bulk uploads may create encrypted IPFS evidence; a manually entered or midterm record may legitimately have no file.
- The genesis record is system initialization metadata and normally has no IPFS file. Do not edit or use it as an academic test record.

Before reporting a missing-file defect, inspect the record and confirm whether an `ipfs_cid` actually exists.

### 12.2 Inspect finalized ledger data

1. Sign in to the application as System Administrator.
2. Select **Infrastructure & Data**.
3. Open **Finalized Grade Ledger**.
4. Search or page to the non-genesis test record by its record, transaction, or Student identifier.
5. Verify the structured fields match the finalized grade shown to the Student.
6. Confirm that raw JSON, wallet databases, MSP material, certificates, credentials, and mutation controls are absent.

Records still being encoded, reviewed, returned, or department-approved remain in PostgreSQL (not the finalized CouchDB world-state database) until finalization succeeds.

### 12.3 Inspect IPFS

1. Open `http://localhost:8080/ipfs-webui/` on a trusted administration workstation.
2. Search for the CID recorded in the finalized grade.
3. Confirm the CID is pinned/available.
4. Use the application **View File** action to test authorized decryption and download.

Do not expose the IPFS administration UI or API publicly.

## 13. Automated developer checks

Run these checks before deployment. Dependency installation changes local package folders but does not change application data.

### 13.1 Frontend tests and production build

```bash
cd frontend
npm install
CI=true npm test -- --runInBand --watchAll=false
npm run build
```

PowerShell equivalent for the test command:

```powershell
$env:CI = "true"
npm test -- --runInBand --watchAll=false
Remove-Item Env:CI
```

### 13.2 Middleware tests

```bash
cd middleware
npm install
npm test
```

### 13.3 Backend restore and build

```bash
dotnet restore client-app/For_Testing_Only_Capstone.sln
dotnet build client-app/For_Testing_Only_Capstone.sln --configuration Release --no-restore
```

### 13.4 Deployment validation

```bash
cd network
./k8s/deploy-k8s.sh local verify
./k8s/deploy-k8s.sh local status
```

Record the date, source commit, command, result, and relevant logs for every failed check.

## 14. Sample acceptance test cases

Use dedicated test accounts and non-production student data. Do not modify `GENESIS-001`. Each case should be marked **Pass**, **Fail**, or **Blocked**, with a screenshot or transaction reference where appropriate.

| ID | Test and precondition | Procedure | Expected result |
|---|---|---|---|
| TC-01 | Fresh local deployment; Kubernetes node is Ready | Run `./k8s/deploy-k8s.sh local apply`, then inspect all four namespaces | Deployment completes; application pods are ready; bootstrap jobs complete; portal opens on port 8080 |
| TC-02 | Deployment is running | Request `/nginx-health`, `/api/backend/health`, middleware `/api/ready`, and .NET gateway `/api/ready` | Health requests succeed and both readiness responses report their required microservices available |
| TC-02A | Fresh deployment completed | List Deployments in `plv-fabric` and inspect the two gateway readiness responses | The middleware gateway/services and all six .NET Deployments are ready; the legacy `client-app` Deployment is absent |
| TC-03 | Valid test accounts exist for all roles | Sign in once as each role | Every account reaches only its authorized portal and actions |
| TC-04 | No generated student exists for the selected test year | Registrar manually adds the first student for Gregorian year 2026 | Student ID is read-only and becomes `26-0001` |
| TC-05 | `26-0001` exists | Registrar manually adds another 2026 student | New student receives `26-0002`; the first ID remains unchanged |
| TC-06 | 2026 students exist; 2027 test sequence is empty | Change enrollment year to 2027 and add a student | New ID is `27-0001`; all 2026 IDs remain unchanged |
| TC-07 | Test environment supports a leap-day date | Add or update permitted test data dated 2028-02-29, then generate a 2028 student | Operation succeeds without a date crash; generated prefix is `28-` |
| TC-08 | Test fixture has reached sequence 9999 for one year | Attempt one more manual student for that year | System rejects creation with a clear 9999-capacity error and creates no duplicate/overflow ID |
| TC-09 | A valid bulk template contains unique ID `26-9001` | Registrar uploads the file | Imported student retains exactly `26-9001`; automatic generation does not replace it |
| TC-10 | Bulk file contains a duplicate or malformed ID | Upload and review validation | Invalid row is rejected with a useful message; existing records are unchanged |
| TC-11 | Student, subject, section, and Faculty account exist | Registrar creates an assignment; Faculty signs in | Assignment appears for the intended Faculty member and students only |
| TC-12 | Encoding period is open | Faculty enters a raw grade of 95 | System displays equivalent `1.25` and does not require Faculty to type it manually |
| TC-13 | Encoding period is open | Test grade boundaries: 98.5, 94, 91, 88, 84, 81, 78, 75, and 74.99 | Equivalents are respectively 1.00, 1.25, 1.50, 1.75, 2.00, 2.25, 2.50, 3.00, and 5.00 |
| TC-14 | Faculty has submitted a test grade | Department Administrator returns it with a reason; Faculty reopens it | Faculty sees the reason, can correct the raw grade, and can resubmit |
| TC-15 | Faculty has submitted a correct test grade | Department Administrator approves it | Record moves to Registrar review; it is not yet shown to Student as finalized |
| TC-16 | Department-approved record is in Registrar queue | Registrar reviews the record | Registrar can review, return, or finalize; no **Correct Grade** action is displayed |
| TC-17 | Registrar has a valid department-approved test record | Registrar finalizes it | Status becomes finalized, a ledger/audit reference is produced, and the Student can see the record |
| TC-18 | A record is finalized | Attempt to edit it from Registrar UI and repeat finalization | No grade-edit action exists; duplicate finalization is prevented or handled idempotently |
| TC-19 | TC-17 completed | As System Administrator, open **Infrastructure & Data -> Finalized Grade Ledger** and find the finalized record | The structured finalized record matches the Student view; raw JSON, wallets, MSP data, certificates, credentials, and edit controls are absent |
| TC-20 | Test record has no `ipfs_cid` | Review its action/file column | UI displays **No File**; no broken **View File** link appears |
| TC-21 | Authorized finals upload produced an `ipfs_cid` | Review and select **View File** | UI displays **View File** and authorized retrieval succeeds |
| TC-22 | Genesis record is visible | Review it without changing it | Genesis remains finalized initialization data, has no Correct Grade action, and may correctly show **No File** |
| TC-23 | Finalized grade belongs to Student A | Sign in as Student A and Student B | Student A sees the record; Student B cannot see Student A's record |
| TC-24 | Application contains finalized and pending test data | Restart affected pods or rerun `local apply`, then sign in and inspect data | Services recover; finalized ledger data and persistent application data remain available |
| TC-25 | Local deployment completed | Try direct browser access to ports 5986, 5990, 6990, 7990, and 9090, then use the protected System Administrator views | Direct ports are closed; finalized grades and Prometheus metrics remain available only through authorized application screens |
| TC-26 | Faculty and Department Administrator accounts exist | Verify login has no **Forgot Password** link; each requester submits an in-portal password-change request | Only Faculty and Department Administrator can submit; no OTP/email receiver is shown or contacted |
| TC-27 | TC-26 request is pending | Registrar approves one request and rejects another with a note | Each requester sees the correct decision; only the approved requester can set a new strong password |
| TC-28 | Prometheus pod is Ready | System Administrator opens **Prometheus Live** | CPU, memory, pod and target values load, target errors are visible, and data refreshes every five seconds |

### 14.1 Test execution record

| Field | Value |
|---|---|
| Test cycle | `<cycle-name>` |
| Environment | `<local/staging/production-like>` |
| Source branch and commit | `<branch>` / `<commit>` |
| Tester | `<name>` |
| Start and end time | `<timestamps>` |
| Passed / Failed / Blocked | `<counts>` |
| Defect references | `<ticket-ids>` |
| Approved by | `<name and date>` |

## 15. Troubleshooting

### 15.1 Portal does not open on port 8080

```bash
cd network
./k8s/deploy-k8s.sh local status
./k8s/deploy-k8s.sh local apply
```

The second command recreates the local frontend port-forward. Also check whether another program already owns port 8080.

### 15.2 A pod is Pending

```bash
kubectl describe pod <pod-name> -n <namespace>
kubectl get pvc --all-namespaces
```

Check resource availability, PersistentVolumeClaims, the storage class, and scheduling events.

### 15.3 A pod is restarting or in CrashLoopBackOff

```bash
kubectl logs <pod-name> -n <namespace>
kubectl logs <pod-name> -n <namespace> --previous
kubectl describe pod <pod-name> -n <namespace>
```

Check missing environment values, failed database connections, certificate mounts, and the first error before later retry messages.

### 15.4 Finalized Grade Ledger does not load

1. Confirm that the signed-in role is System Administrator.
2. Open **Infrastructure & Data -> Finalized Grade Ledger**; do not type a CouchDB port manually.
3. Check the `dotnet-operations-service` and Registrar CouchDB pod readiness.
4. Confirm the internal CouchDB credentials are present in the Kubernetes secret without printing them.
5. Redeploy or rotate credentials through the approved procedure when the backend reports an authentication failure.

Direct CouchDB login is intentionally disabled for users. Do not expose or paste CouchDB credentials into logs, screenshots, chat, or issue trackers.

### 15.5 TLS handshake errors in peer or orderer logs

An isolated handshake message can be caused by a plain HTTP probe or connection to a TLS-only Fabric port. If transactions and readiness checks still work, correlate the timestamp and source before treating it as an outage. If operations fail:

```bash
kubectl get pods --all-namespaces
kubectl get secret -n plv-main-campus
kubectl logs <orderer-or-peer-pod> -n <namespace> --since=15m
```

Check certificate validity, mounted TLS paths, hostname/server-name settings, peer/orderer endpoints, and whether a client is using the correct TLS scheme. Never disable Fabric TLS as a production workaround.

### 15.6 Grade is not visible in the finalized ledger view

- Confirm the record has completed Registrar finalization.
- Use the System Administrator **Finalized Grade Ledger** view, not a direct CouchDB port or wallet database.
- Pending, returned, submitted, and department-approved records remain in PostgreSQL.
- Refresh the protected application view after confirming the Registrar CouchDB and operations service are Ready.

### 15.7 UI says No File

Inspect the record's `ipfs_cid`. If it is empty, **No File** is correct. If a CID exists but the UI still says **No File**, capture the non-sensitive record ID, browser console error, and backend/middleware logs. Do not alter the genesis record to test file behavior.

## 16. Logs and operational evidence

Useful commands:

```bash
kubectl logs deployment/middleware-api -n plv-fabric --since=15m
kubectl get events --all-namespaces --sort-by=.lastTimestamp
kubectl get pods --all-namespaces -o wide
```

For a specific failing pod:

```bash
kubectl logs <pod-name> -n <namespace> --since=15m
kubectl describe pod <pod-name> -n <namespace>
```

Redact tokens, passwords, connection strings, personal student information, and encryption keys before sharing evidence.

## 17. Shutdown and removal

To remove the local Kubernetes deployment and stop deployment-managed port-forwards:

```bash
cd network
./k8s/deploy-k8s.sh local delete
```

Deletion can remove Kubernetes resources and may affect test data. Export required evidence and verify the intended Kubernetes context before running it. Production removal requires an approved change plan and verified backups.

## 18. Release acceptance checklist

- [ ] Automated frontend tests pass.
- [ ] Frontend production build succeeds.
- [ ] Middleware tests pass.
- [ ] Backend Release build succeeds.
- [ ] Kubernetes verification and readiness checks pass.
- [ ] Role-based login and access-control tests pass.
- [ ] Manual and bulk student ID tests pass.
- [ ] Gregorian leap-year and 9999-limit tests pass.
- [ ] Raw-to-college grade boundary tests pass.
- [ ] Faculty return/resubmit workflow passes.
- [ ] Department approve/return workflow passes.
- [ ] Registrar review/return/finalize workflow passes without Correct Grade.
- [ ] Finalized data is visible only in the protected structured **Finalized Grade Ledger** view; direct CouchDB ports remain closed.
- [ ] Prometheus Live loads current metrics and target health through the System Administrator portal; port 9090 remains closed.
- [ ] Faculty/Department Administrator password requests and Registrar approve/reject decisions work without Forgot Password, OTP, or SMTP reset messages.
- [ ] IPFS View File and No File behavior matches the presence of `ipfs_cid`.
- [ ] Genesis record remains unchanged.
- [ ] Persistence/restart test passes.
- [ ] Test evidence is redacted, reviewed, and signed off.
