# IAM roles for the broker task.
#
#   * Execution role — used by the ECS agent to pull the image, write logs,
#     and resolve the Secrets Manager values injected into the container.
#   * Task role — the application's own identity. Deliberately minimal:
#     kms:Decrypt / kms:GenerateDataKey on the single credential-encryption
#     key, and read on the three broker secrets. Nothing else: the broker's
#     blast radius if compromised is bounded to what it already brokers.

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# --- Execution role ---------------------------------------------------------

resource "aws_iam_role" "task_execution" {
  name               = "${local.name_prefix}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The execution role materialises the container `secrets` mappings, so it
# needs read access to the broker secrets (they use the AWS-managed
# Secrets Manager KMS key, so no extra kms:Decrypt grant is required).
data "aws_iam_policy_document" "execution_secrets_read" {
  statement {
    sid     = "ReadBrokerSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.jwt_signing.arn,
      aws_secretsmanager_secret.google_oauth.arn,
      aws_secretsmanager_secret.database.arn,
    ]
  }
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name   = "${local.name_prefix}-execution-secrets"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.execution_secrets_read.json
}

# --- Task role --------------------------------------------------------------

resource "aws_iam_role" "task" {
  name               = "${local.name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "task_permissions" {
  # Envelope encryption of stored provider credentials
  # (credbroker/crypto/kms.py: GenerateDataKey on write, Decrypt on invoke).
  statement {
    sid = "CredentialEnvelopeEncryption"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.credentials.arn]
  }

  # Read-only access to the broker's own secrets (e.g. key rotation or
  # re-reading configuration at runtime).
  statement {
    sid     = "ReadBrokerSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.jwt_signing.arn,
      aws_secretsmanager_secret.google_oauth.arn,
      aws_secretsmanager_secret.database.arn,
    ]
  }
}

resource "aws_iam_role_policy" "task_app" {
  name   = "${local.name_prefix}-task-app"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_permissions.json
}
