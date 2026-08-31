# CredBroker

A scoped credential broker for MCP tool calls. Agents never hold real credentials. They hold short lived grants instead. The broker performs the actual API calls on their behalf and records every action.

## The Problem

AI agents act through tools that call real services such as Google Drive or Slack or GitHub. Each of those services expects an OAuth token. Handing that token to an agent creates a standing liability. The token lives for a long time. It usually carries broad access. It can leak through logs or transcripts or prompt injection. A leaked token keeps working until someone notices.

## The Approach

CredBroker keeps every credential inside one service. An agent that wants to act must first ask the broker for a grant. A grant is a signed pass that expires after five minutes and authorizes one class of action. The agent presents the pass when it wants the action performed. The broker validates the pass. It then decrypts the real credential inside its own process and calls the provider. Only the result leaves the broker. Every issuance and every call lands in an audit log. A grant can be revoked at any moment. Revocation reaches calls that are already in flight.

## System Architecture
<img width="1983" height="918" alt="architecture" src="https://github.com/user-attachments/assets/ccd89b74-ba1e-4923-bea8-4dffed64cbbf" />

## How a Call Flows

1. A user connects a Google account through a standard OAuth consent screen.
2. The broker exchanges the consent code for tokens and encrypts them before storage.
3. An agent requests a grant for a tool such as drive.read.
4. The broker checks the agent policy and signs a JWT with a five minute lifetime.
5. The agent calls InvokeTool with the grant token.
6. The broker verifies the token and decrypts the stored credential internally.
7. The broker calls the provider and returns only the result.
8. An audit row records the outcome with latency and an argument hash.

## Security Model

* Stored credentials are protected by envelope encryption. Each credential gets a fresh AES data key and AWS KMS wraps that key.
* The database stores only a hash of each grant token. Possession of the database is not possession of a usable pass.
* Grant issuance is serialized with a database row lock. Concurrent requests cannot race past the policy limits.
* Each agent belongs to one user. A grant can only bind to an account owned by that user.
* Revocation writes to both Postgres and Redis. The invoke path checks again right before the outbound call.
* A redaction filter scrubs registered secrets from every log line including tracebacks.
* Idempotency keys deduplicate retried calls that have side effects.
* Outbound provider calls get exponential backoff and a circuit breaker.
* Regression tests pin each of these properties.

## Quick Start

The demo needs no credentials at all.

```
make demo
```

Then open http://localhost:8000/console

This starts the full stack in Docker. The stack includes the broker together with Postgres and Redis and Prometheus and Grafana. It also includes a bundled fake Drive service. The seeded demo agent can request grants and invoke drive.read against it. The whole lifecycle works end to end without a Google account.

## The Operator Console

The console at /console makes the security model visible. It draws the credential path as a live schematic. Authorized calls light the path. The vault sits inside a drawn containment boundary that no credential ever crosses. A five step procedure runs the real lifecycle against the running broker. An annunciator wall shows one window per call with its outcome and latency.

The console deliberately plays the agent role. Requesting a grant shows the signed token exactly once. That is the point. You can then invoke with it and revoke it and watch the next call get denied.

Set CREDBROKER_CONSOLE_TOKEN to require a token header on the console API. An empty value leaves the console open and suits local development only.

## Development

```
make install
make test
make lint
```

The test suite runs entirely offline. It uses SQLite in place of Postgres. It uses a fake Redis and a local key manager in place of AWS. There are 209 tests including a dedicated suite that proves raw tokens never appear in logs or responses or the database.

Copy the example environment file to configure a local run.

```
cp .env.example .env
```

## Interfaces

Agents talk to the broker over gRPC. The service exposes RequestGrant and InvokeTool and RevokeGrant. Browsers use a small HTTP surface for the OAuth consent flow and the console and health checks and metrics. The protobuf definition lives in credbroker/proto.

## Repository Guide

* credbroker/db defines the schema. It covers connected accounts and agents and grants and the audit log.
* credbroker/crypto implements envelope encryption with a KMS backend for production and a local backend for development.
* credbroker/oauth implements the Google consent flow with a signed state parameter.
* credbroker/grants issues and revokes grants and signs the JWTs.
* credbroker/invoke is the path that validates grants and decrypts credentials and proxies provider calls.
* credbroker/tools holds the provider adapters.
* credbroker/reliability provides retries and the circuit breaker and the idempotency store.
* credbroker/cache provides the Redis grant cache and rate limiting.
* credbroker/grpcserver serves the agent API.
* credbroker/console serves the operator console and its REST API.
* credbroker/demo provides the fake Drive service and the demo seeder.
* alembic holds the schema migrations.
* infra/terraform describes the AWS deployment.
* observability holds the Prometheus scrape config and the Grafana dashboard.

## Real Providers

The demo points drive.read at the bundled fake Drive through the CREDBROKER_DRIVE_API_BASE_URL variable in the Compose file. Remove that entry to target the real Drive API. Real mode also needs an OAuth client from the Google Cloud console. Put its identifier and secret in your local environment file. Then connect an account from the console.

## Deployment

The Terraform under infra/terraform provisions the production stack on AWS. It creates the network and an ECS Fargate service and RDS Postgres and ElastiCache Redis and a KMS key and Secrets Manager entries and a load balancer with autoscaling.

GitHub Actions runs lint and tests and an image build on every change. Pushes to main also publish the image to ECR. The Terraform jobs stay inert until the TERRAFORM_ENABLED repository variable is set. Configure the state backend first. Secrets never pass through Terraform or the pipeline. They are seeded directly into Secrets Manager.

The .railway directory defines a Railway deployment of the same container in code. Railway applies the migrations as a predeploy step before each release goes live. A hosted demo instance runs the bundled fake Drive so the console works there without any Google credentials.

## Observability

The broker exposes Prometheus metrics at /metrics. They cover grant issuance and denials and invoke latency and failures and revocations and rate limiting. The demo stack provisions a Grafana dashboard on port 3000.

## Scope

The first version supports Google as the only provider. The pattern generalizes and the adapter interface is ready for more. Scoping applies to whole tools rather than individual resources. The deployment targets a single region.
