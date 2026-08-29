# Secrets Manager secrets consumed by the broker task definition (ecs.tf
# injects individual JSON keys via the container "secrets" mapping, so secret
# values never appear in the task definition or in Terraform-rendered env).
#
# Two of the secrets hold operator-provided material and are created EMPTY on
# purpose — Terraform must never hold a JWT private key or an OAuth client
# secret in state. Populate them once, out of band, before the first deploy:
#
#   aws secretsmanager put-secret-value \
#     --secret-id credbroker-prod/jwt-signing \
#     --secret-string '{"private_key_pem":"-----BEGIN PRIVATE KEY-----\n...","public_key_pem":"-----BEGIN PUBLIC KEY-----\n..."}'
#
#   aws secretsmanager put-secret-value \
#     --secret-id credbroker-prod/google-oauth \
#     --secret-string '{"client_id":"...","client_secret":"...","oauth_state_secret":"..."}'
#
# ECS tasks fail to launch until both are populated — a deliberate fail-closed
# default for a credential broker.

# RS256 keypair used to sign/verify grant tokens.
# Expected JSON keys: private_key_pem, public_key_pem.
resource "aws_secretsmanager_secret" "jwt_signing" {
  name                    = "${local.name_prefix}/jwt-signing"
  description             = "CredBroker grant-token RS256 signing keypair (keys: private_key_pem, public_key_pem)"
  recovery_window_in_days = 7
}

# Google OAuth application credentials plus the HMAC secret for the OAuth
# state parameter. Expected JSON keys: client_id, client_secret,
# oauth_state_secret.
resource "aws_secretsmanager_secret" "google_oauth" {
  name                    = "${local.name_prefix}/google-oauth"
  description             = "CredBroker Google OAuth client (keys: client_id, client_secret, oauth_state_secret)"
  recovery_window_in_days = 7
}

# --- Database credentials ---------------------------------------------------
# The master password is generated here and stored only in Secrets Manager
# (and, unavoidably, Terraform state — use an encrypted remote backend).
# special=false keeps the password URL-safe for the SQLAlchemy DSN.

resource "random_password" "db_master" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "database" {
  name                    = "${local.name_prefix}/database"
  description             = "CredBroker RDS credentials and SQLAlchemy URL (keys: username, password, url)"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id

  secret_string = jsonencode({
    username = aws_db_instance.postgres.username
    password = random_password.db_master.result
    url      = "postgresql+asyncpg://${aws_db_instance.postgres.username}:${random_password.db_master.result}@${aws_db_instance.postgres.address}:${aws_db_instance.postgres.port}/${aws_db_instance.postgres.db_name}"
  })
}
