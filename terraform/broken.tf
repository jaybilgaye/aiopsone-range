###############################################################################
# The planted misconfigurations.
#
# Each block below maps to a specific finding the lessons walk through. The
# comment names the check so you can match the scanner output to the cause.
#
#   checkov -d terraform/
#   trivy config terraform/
#
# The fixes live in the lessons, not here. This file stays broken.
###############################################################################

# --- FLAW 1: public S3 bucket -------------------------------------------------
# Checkov: CKV_AWS_20 (public read), CKV_AWS_53-56 (Block Public Access)
# Prowler / Security Hub: S3.1, S3.2, S3.3, S3.8 · CIS 1.20
# Lesson: "Fix: Public S3 Buckets"

resource "aws_s3_bucket" "public_data" {
  bucket        = "${var.name_prefix}-public-data-${random_id.suffix.hex}"
  force_destroy = true # so `terraform destroy` actually works in a lab
}

resource "random_id" "suffix" {
  byte_length = 4
}

# Deliberately disabling every guard rail AWS turns on by default.
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadEverything"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_data.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.public_data]
}

# --- FLAW 2: no encryption at rest, no versioning, no access logging ---------
# Checkov: CKV_AWS_19 (encryption), CKV_AWS_21 (versioning), CKV_AWS_18 (logging)
# Lesson: "Fix: Encryption at Rest"
# (Note: AWS now applies SSE-S3 by default; the finding here is the absent
#  explicit configuration and the absent versioning/logging, which scanners flag.)

# --- FLAW 3: security group open to the world --------------------------------
# Checkov: CKV_AWS_24 (SSH from 0.0.0.0/0), CKV_AWS_260
# Prowler / Security Hub: EC2.13, EC2.14 · CIS 5.2
# Lesson: "Fix: Security Groups Open to the World"

resource "aws_security_group" "wide_open" {
  name        = "${var.name_prefix}-wide-open"
  description = "INTENTIONALLY VULNERABLE - do not use"

  ingress {
    description = "SSH from anywhere - this is the finding"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- FLAW 4: over-permissioned IAM -------------------------------------------
# Checkov: CKV_AWS_1, CKV_AWS_62, CKV_AWS_63 (wildcard action + resource)
# Prowler / Security Hub: IAM.1 · CIS 1.16
# Lesson: "How IAM policy evaluation actually works", "IAM Policy Linter"
#
# Note this is also a privilege-escalation path: iam:PassRole combined with a
# compute service lets the holder assume any role in the account.

resource "aws_iam_role" "over_permissioned" {
  name = "${var.name_prefix}-too-much-access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "admin_everything" {
  name = "${var.name_prefix}-admin-everything"
  role = aws_iam_role.over_permissioned.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WildcardEverything"
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# --- FLAW 5: no CloudTrail ---------------------------------------------------
# There is deliberately no aws_cloudtrail resource in this configuration.
# Prowler / Security Hub: CloudTrail.1, CloudTrail.2, CloudTrail.4 · CIS 3.1
# Lesson: "Fix: CloudTrail Not Multi-Region or Missing Log File Validation"
#
# An absent resource is a finding a scanner cannot see in the Terraform — only
# a posture scan of the live account catches it. That contrast is the point of
# the RUN chapter, and why IaC scanning alone is not enough.

output "what_you_just_built" {
  description = "Summary of the deliberate weaknesses, for the lesson walkthrough."
  value = {
    public_bucket = aws_s3_bucket.public_data.id
    open_sg       = aws_security_group.wide_open.id
    admin_role    = aws_iam_role.over_permissioned.name
    missing       = "CloudTrail, GuardDuty, Config, access logging, encryption config"
    reminder      = "terraform destroy when you are done. Check your billing alarm."
  }
}
