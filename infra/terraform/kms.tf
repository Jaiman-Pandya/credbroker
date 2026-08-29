# KMS key for envelope encryption of provider credentials.
#
# The broker calls kms:GenerateDataKey to wrap a fresh AES-256 data key per
# stored token and kms:Decrypt to unwrap it inside the invoke path (see
# credbroker/crypto/kms.py). Raw OAuth tokens therefore never touch disk
# unencrypted, and the master key never leaves KMS. The task role in iam.tf
# is the only principal granted use of this key besides the account root.

resource "aws_kms_key" "credentials" {
  description             = "CredBroker envelope encryption of stored provider credentials"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-credentials"
  }
}

resource "aws_kms_alias" "credentials" {
  name          = "alias/${local.name_prefix}-credentials"
  target_key_id = aws_kms_key.credentials.key_id
}
