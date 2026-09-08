# BlockGO delivery workflow

The repository uses a two-stage GitHub Actions promotion path:

`Backup-2` -> `Staging-and-Testing` -> `main`

The capitalization above matches the existing Git branch. Do not create a separate `Staging-And-Testing` branch.

## Quality gates

Every push and pull request for the three delivery branches runs the complete `Quality Gates` workflow:

1. TDD tests for the middleware, React frontend, ASP.NET services, and Go chaincode.
2. CodeQL scanning for JavaScript/TypeScript and C#.
3. Generated-secret and runtime-ledger rejection.
4. Pull-request dependency review and production dependency audits.
5. Deployment-script, GitHub-workflow, and Kubernetes manifest validation.
6. Strict public-route and blocked-database-route smoke tests.
7. XP-style concurrent route stress tests with explicit error and latency thresholds.
8. The final required `quality-gate` status, which fails unless every applicable job succeeded.

After a successful `Backup-2` push, the workflow reapplies/verifies GitHub branch governance and then calls `promote.yml` to create an auto-merge pull request into staging. Staging runs every gate for the pull request and runs the complete suite again after merge. Only a successful staging push, followed by another governance verification, can create the pull request into `main`, where the pull request runs all gates again.

## Required secrets

- `PROMOTION_TOKEN`: fine-grained token with Contents read/write and Pull requests read/write. It must be able to create pull requests whose events trigger Actions.
- `GOVERNANCE_TOKEN`: fine-grained token with repository Administration read/write.

`Configure Branch Governance` is reusable and can also be run manually from the Actions tab. The delivery workflow invokes it automatically after successful `Backup-2` and staging pushes. It protects `Staging-and-Testing` and `main`, requires pull requests and the `quality-gate` status, applies checks to administrators, requires current branches and resolved conversations, and disables force-pushes and branch deletion. Pull requests require zero human approvals so the gated promotion can remain automatic, but direct pushes cannot bypass the staging rerun.
