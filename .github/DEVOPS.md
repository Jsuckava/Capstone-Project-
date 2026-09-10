# BlockGo CI/CD and DevSecOps

## Promotion path

```text
Develop-and-Integration
        -> feature/api-endpoints-Testing
        -> Staging-and-Testing
        -> main
        -> production environment / GKE
```

Each promotion workflow verifies that the source branch still points to the exact
commit that passed its quality gate. Production is manual, accepts only the current
`main` head, and requires the `DEPLOY_MAIN` confirmation.

## Required branch checks

Configure branch protection or repository rulesets with these required checks:

| Branch | Required check |
| --- | --- |
| `Develop-and-Integration` | `Required Develop CI Gate` |
| `feature/api-endpoints-Testing` | `Required Feature/API Gate` |
| `Staging-and-Testing` | `Required Staging Gate` |
| `main` | `Required Security Gate` |

Require pull requests, prevent force pushes and branch deletion, dismiss stale
approvals, and require branches to be current before merging. Enable GitHub code
scanning and dependency graph features so CodeQL and dependency review can publish
their complete results.

## Security coverage

- actionlint validation for workflow syntax and expressions
- repository hygiene checks for tracked credentials and runtime data
- CodeQL analysis for JavaScript/TypeScript, C#, and Go
- dependency review for pull-request dependency changes
- Trivy filesystem, secret, dependency, IaC, and container-image scanning
- npm and NuGet production dependency audits
- CycloneDX repository and image SBOM artifacts
- Schemathesis OpenAPI fuzzing plus ZAP and Nuclei DAST
- frontend, middleware, chaincode, ASP.NET, enrollment, container, and SPA-route tests
- Dependabot updates for Actions, npm, NuGet, Go, pip, and Docker

High or critical dependency/image/IaC findings and any detected secret block their
quality gate. ZAP and Nuclei enforce the policies in `security/`.

## Production environment

Create a protected GitHub environment named `production` and require reviewer
approval. Configure these repository or environment values:

### Variables

- `GCP_PROJECT_ID`
- `GKE_CLUSTER_NAME`
- `GKE_REGION`
- `PRODUCTION_IMAGE_REPOSITORY`
- `PRODUCTION_BASE_URL` (optional external smoke-test base URL)

`PRODUCTION_IMAGE_REPOSITORY` must be an Artifact Registry path under
`GKE_REGION-docker.pkg.dev/GCP_PROJECT_ID/`.

### Secrets

- `GCP_WORKLOAD_IDENTITY_PROVIDER`
- `GCP_DEPLOY_SERVICE_ACCOUNT`
- `BLOCKGO_PRODUCTION_ENV_B64`
- `PROMOTION_TOKEN`

Use Google Workload Identity Federation for the deploy service account; do not store
a long-lived Google service-account key in GitHub. `BLOCKGO_PRODUCTION_ENV_B64` is
the base64 encoding of the production `network/.env` contents. The workflow writes
it with owner-only permissions for deployment and shreds the temporary file afterward.

## Current security blockers

The repository hygiene gate intentionally rejects tracked logs, IPFS runtime data,
Fabric keystores, and private-key filenames. Before making this gate required:

1. Rotate every credential or token that appears in tracked files.
2. Remove runtime data and private keys from the Git index while preserving any
   operational copies outside the repository.
3. Purge sensitive historical blobs with an approved history-rewrite procedure.
4. Re-clone and re-scan the rewritten repository before enabling promotion.

Do not add a baseline or allowlist for real credentials. Examples and templates must
contain placeholders only.
