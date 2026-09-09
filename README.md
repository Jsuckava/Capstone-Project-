# PLV Blockchain Grades Ledger

A highly secure, microservices-based grading ledger and identity management system built for Pamantasan ng Lungsod ng Valenzuela (PLV). This project integrates traditional Web2 relational databases with Web3 Hyperledger Fabric blockchain technology to ensure absolute immutability, transparency, and security of student records.

>  **Deep Dive:** For full System Architecture diagrams, Data Flow Diagrams (DFD), and detailed sequence workflows, please see the [System Architecture & Data Flow Guide (Guide.md)](./Guide.md).

---

## System Architecture & Tech Stack

This system utilizes a clean separation of concerns, splitting standard database orchestration from cryptographic blockchain operations.

### 1. Frontend (React.js)
- Serves as the user interface for Students, Faculty, Department Admins (Deans), and the Registrar.
- Hosted securely behind an **Nginx Reverse Proxy** (Port 80), eliminating the need for users to specify ports.
- Communicates with backends via JWT authorization.

### 2. Database Services (ASP.NET Core / C#)
- **Gateway port:** 5000 (Internal)
- **Service ports:** 5101-5105 (ClusterIP-only)
- Runs as an API gateway plus independently deployed auth/account, academic, grade, operations, and realtime services.
- Manages the **PostgreSQL** relational database (`ActivityLogs`), waitlist, profile data, assignments, grade workflows, monitoring, and SignalR notifications.
- Preserves the existing `/api/*` and `/chatHub` contracts through `client-app-service`, so the frontend and Node.js middleware do not need service-specific URLs.
- Uses the existing Node.js middleware gateway for cryptographic and blockchain operations.

### 3. Blockchain Bridge / Middleware (Node.js & Express)
- **Gateway port:** 4000 (Internal)
- **Role:** Web3 & Cryptography microservices.
- Integrates the **Hyperledger Fabric SDK**.
- Manages X.509 Cryptographic Certificates, JWT generation, and bcrypt password hashing.
- Submits and queries smart contract (Chaincode) transactions on the Fabric Ledger, mapping users to a secure CouchDB Wallet.

### 4. Distributed Network (Docker)
- **Hyperledger Fabric (v2.5.4):** 3 Organizations (RegistrarMSP, FacultyMSP, DepartmentMSP) with 2 Peers each.
- **State Database:** CouchDB for rich queries.
- **Chaincode:** Go-based Smart Contract running as a Service (CCaaS).
- **Storage:** IPFS (InterPlanetary File System) nodes for distributed file/asset storage.

---

## Nginx Reverse Proxy Configuration

The Nginx container (`nginx-shield`) acts as the single entry point for all incoming HTTP traffic. It intelligently routes requests to the appropriate backend microservice and serves the static React frontend, simplifying the architecture and enhancing security.

The configuration, located at `middleware/nginx/nginx.conf`, is as follows:

```nginx
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    # Define upstream servers to allow for easy service discovery via Docker DNS
    upstream client_app_backend { server client-app:5000; }
    upstream middleware_backend { server middleware:4000; }

    # Server block to redirect all HTTP traffic to HTTPS
    server {
        listen 80;
        server_name localhost;
        return 301 https://$host$request_uri;
    }

    # Main server block to handle HTTPS traffic
    server {
        listen 443 ssl;
        server_name localhost;

        # SSL Certificate paths (inside the container)
        ssl_certificate /etc/nginx/ssl/localhost.crt;
        ssl_certificate_key /etc/nginx/ssl/localhost.key;

        # --- Security Enhancements ---
        # Use modern TLS protocols
        ssl_protocols TLSv1.2 TLSv1.3;
        # Use a strong cipher suite
        ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
        ssl_prefer_server_ciphers off;

        # --- Application Routing ---

        # Route Web2 API calls to the C# Backend (most specific match first)
        location /api/Auth/ {
            proxy_pass http://client_app_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Route Web3/Crypto API calls to the Node.js Middleware
        location /api/ {
            proxy_pass http://middleware_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Serve React Frontend for all other requests
        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
            try_files $uri $uri/ /index.html; # Required for React Router
        }
    }
}
```

---

##  User Roles & Workflows

### 1. The Registrar (Master Admin)
- **Waitlist Management:** Approves newly registered users (Students, Faculty, and Staff).
- **Assignment:** Assigns approved Department Admins to specific colleges (e.g., CS, IT) and assigns approved Faculty to specific departments, sections, and year levels.
- **Assignments (Students):** Routes approved students to a specific Department and Section.
- **Ledger:** Finalizes grades and commits them permanently to the blockchain.

### 2. Department Admin (Dean)
- **Enrollment:** Reviews students assigned to their department by the Registrar and officially "Enrolls" them.
- **Grade Verification:** Reviews grades issued by faculty members within their department and "Approves" them for Registrar finalization.

### 3. Faculty
- **Grade Issuance:** Creates new grade records on the blockchain using the `IssueGrade` smart contract function.
- **Visibility:** Can only view grades they personally issued, or grades related to their specific department assignments.

### 4. Student
- **Visibility:** Has strictly limited access. Can only view their own finalized grades.

---

## Quick Start & Deployment Guide

### Prerequisites
- Ubuntu/Debian (or WSL2 on Windows)
- Docker & Docker Compose
- Node.js (v20+)
- .NET 8.0 SDK

### Step 1: Deploy the Network
Navigate to the `network` directory and run the automated deployment script. This script installs dependencies, generates secure passwords, builds the blockchain network, and starts both backend servers and the frontend.

```bash
cd network
chmod +x full_deploy.sh
./full_deploy.sh
```

### Step 2: Bootstrap the Root Registrar
Because the system utilizes a strict waitlist, a "Catch-22" exists where you need an admin to approve an admin. To bypass this for the initial setup, you must call the bootstrap endpoint with your `INTERNAL_API_KEY`:

**Command:**
```bash
curl -X GET http://localhost/api/bootstrap -H "x-api-key: your-internal-api-key"
```

*This will securely inject `registrar@plv.edu.ph` into PostgreSQL and instantly generate their Hyperledger Fabric wallet using the `MOCK_REGISTRAR_PASS` defined in your environment.*

### Step 3: Access the Portal
Navigate to **http://localhost** in your browser.
Log in using the bootstrapped credentials:
- **Email:** `registrar@plv.edu.ph`
- **Password:** [Your environment-defined MOCK_REGISTRAR_PASS]

---

## Environment Configuration
The following environment variables are **mandatory** and must be defined in your `network/.env` file before deployment:

| Variable | Description |
| :--- | :--- |
| `JWT_SECRET` | A long, secure random string for JWT signing. |
| `INTERNAL_API_KEY` | Secure key for cross-service authentication. |
| `POSTGRES_PASS` | Password for the PostgreSQL database cluster. |
| `BOOTSTRAP_REGISTRAR_PASS` | Admin password for the Fabric Certificate Authorities. |
| `IPFS_ENCRYPTION_KEY` | 32-character key for encrypting IPFS grading sheets. |
| `MOCK_REGISTRAR_PASS` | Password for the initial bootstrapped registrar account. |

---

##  Directory Structure

```text
Capstone-Project/
├── chaincode/               # Go Smart Contract (CCaaS)
├── client-app/              # C# ASP.NET Core Backend (Lobby/PostgreSQL Logic)
│   ├── Controllers/         # AuthController.cs (Assignments & Waitlist)
│   └── appsettings.json     # DB Connections & Smtp Config
├── frontend/                # React.js UI Portal
│   ├── src/
│   │   ├── api.js           # API Wrapper (Handles routing & JWTs)
│   │   └── GradesDashboard.jsx # Main Dashboard UI
├── middleware/              # Node.js microservices and stable API gateway
│   ├── middleware.js        # Compatibility launcher for the API gateway
│   ├── src/services/        # Auth, identity, ledger, upload, and settings processes
│   ├── src/fabric/          # Shared CA, wallet, and Gateway adapters
│   └── nginx/               # Nginx reverse-proxy configuration
├── Guide.md                 # System Architecture, DFDs, and Sequence Diagrams
└── network/                 # Docker Compose & Fabric Configs
    ├── crypto-config/       # Auto-generated X.509 certificates
    ├── fabric-ca/           # Certificate Authority Configs
    ├── channel-artifacts/   # Genesis block & channel transactions
    ├── cleanup.ps1          # Complete environment reset utility
    └── full_deploy.sh       # Master startup script
```

---

##  API Flow Example (Registration & Approval)

1. **Signup Request:**
   - Frontend (`React`) sends POST to `/api/Auth/request`.
   - Nginx routes `/api/Auth/*` to **C# (Port 5000)**.
   - C# pauses, sends POST to **Node.js (Port 4000)** `/api/crypto/hash-password`.
   - Node.js returns the `bcrypt` hash.
   - C# saves the user to PostgreSQL with status `pending`.

2. **Approval:**
   - Registrar clicks "Approve".
   - Frontend sends PUT to `/api/Auth/requests/approve/...`.
   - C# updates PostgreSQL status to `APPROVED`.
   - C# sends internal POST to **Node.js (Port 4000)** `/api/fabric/register-user`.
   - Node.js registers the user with `ca.registrar.capstone.com`, downloads their certificate, and saves it to the local `/wallet`.

---

## Troubleshooting & Helpful Commands

**View Node.js Middleware Logs:**
```bash
cd middleware
cat middleware.log
```

**View C# Backend Logs:**
```bash
cd client-app
cat backend.log
# Or view Serilog text files in client-app/logs/
```

**Restart Nginx Proxy (If React isn't updating):**
```bash
cd network
docker compose restart nginx-shield
```

**Database Backup:**
```bash
cd network
./backup_postgres.sh
```

**Check Chaincode Container:**
```bash
docker logs registrar-chaincode
```

---

*Project architecture designed and maintained for robust security, immutable auditing, and strict attribute-based access control (ABAC).*
