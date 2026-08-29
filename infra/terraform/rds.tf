# PostgreSQL for connected accounts (envelope-encrypted tokens), agents,
# grants, and the audit log. Single-AZ db.t4g.micro is the deliberate v1
# footprint (see docs/DESIGN.md non-goals); private subnets only, reachable
# solely from the broker service security group.

resource "aws_db_subnet_group" "postgres" {
  name       = "${local.name_prefix}-postgres"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}

resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds"
  description = "RDS Postgres: ingress only from the broker service"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from broker tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.broker_service.id]
  }

  tags = {
    Name = "${local.name_prefix}-rds"
  }
}

resource "aws_db_instance" "postgres" {
  identifier     = "${local.name_prefix}-postgres"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  db_name  = "credbroker"
  username = "credbroker"
  password = random_password.db_master.result
  port     = 5432

  allocated_storage = var.db_allocated_storage_gb
  storage_type      = "gp3"
  storage_encrypted = true

  multi_az               = false
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  deletion_protection        = var.db_deletion_protection

  # This database carries envelope-encrypted user credentials: always leave a
  # final snapshot behind on destroy.
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name_prefix}-postgres-final"

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}
