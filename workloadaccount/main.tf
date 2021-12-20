/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

provider "aws" {
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}
data "aws_organizations_organization" "current" {}

# Use the output information from the terraform code for the security and logging account to populate the local variables.
# The variable names match their respective values from the security and logging terraform code.

locals {
SessionManagerKeyArn = ""
SessionManagerS3LoggingBucketName = ""
SessionManagerS3LoggingBucketNameAccountId = ""
}

data "aws_iam_policy_document" "EC2SSMSession" {


  statement {

    sid = "S3PermissionsToWriteLogfiles"

    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetEncryptionConfiguration"
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/$${aws:PrincipalAccount}/*",
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:ResourceAccount"
      values = [
        local.SessionManagerS3LoggingBucketNameAccountId
      ]
    }
  }

  # When Systems Manager Session Manager sessions are created additional metadata referred to as EncryptionContext is generated.
  # Since it can expected that this information to be present in requests to perform decryption againt the data key encrypting the session this condition
  # can be used to constrain permissions to use the KMS key.

  statement {

    sid = "KMSPermissionsToDecryptSessionDataKey"

    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:Decrypt",
    ]

    resources = [
      local.SessionManagerKeyArn,
    ]

    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:aws:ssm:SessionId"
      values = [
        "false"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:ssm:TargetId"
      values = [
        "i-*"
      ]
    }
  }

  # When objects are stored in S3 using server side encryption additional metadata referred to as EncryptionContext is generated.
  # Since it can expected that this information to be present in requests to create data keys to store logs this condition
  # can be used to constrain permissions to use the KMS key.
  # Note This variant of the statement applies when the target S3 bucket is configured NOT to use a BucketKey.

  statement {

    sid = "KMSPermissionsToEncryptS3ObjectsWithoutBucketKeyEnabled"

    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]

    resources = [
      local.SessionManagerKeyArn,
    ]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/$${aws:PrincipalAccount}/*"
      ]
    }
  }

  # When objects are stored in S3 using server side encryption additional metadata referred to as EncryptionContext is generated.
  # Since it can expected that this information to be present in requests to create data keys to store logs this condition
  # can be used to constrain permissions to use the KMS key.
  # Note This variant of the statement applies when the target S3 bucket is configured to use a BucketKey

  statement {

    sid = "KMSPermissionsToEncryptS3ObjectsWhenBucketKeyEnabled"

    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]

    resources = [
      local.SessionManagerKeyArn,
    ]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}"
      ]
    }
  }

}

resource "aws_iam_policy" "SSMIAMPolicy" {
  name        = "SystemsManagerSessionLoggingandEncryptionPermissions"
  path        = "/common/examples/"
  description = "Policy permissions to allow role to make use of KMS encrypted sessions and write encrypted logs to designated bucket"
  policy      = data.aws_iam_policy_document.EC2SSMSession.json
}

resource "aws_iam_role" "SessionRole" {
  name = "EC2-SSMEncryptedandLoggedSessions"
  path = "/common/examples/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

}

resource "aws_iam_instance_profile" "SessionRole" {
  name = aws_iam_role.SessionRole.name
  path = "/common/examples/"
  role = aws_iam_role.SessionRole.name
}

resource "aws_iam_role_policy_attachment" "SessionRoleSSMIAMPolicy" {
  role       = aws_iam_role.SessionRole.name
  policy_arn = aws_iam_policy.SSMIAMPolicy.arn
}

resource "aws_iam_role_policy_attachment" "SessionRoleSSMCore" {
  role       = aws_iam_role.SessionRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "null_resource" "cleanupexistingSSM-SessionManagerRunShell" {
  provisioner "local-exec" {
    command    = "aws ssm delete-document --name SSM-SessionManagerRunShell --region ${data.aws_region.current.name}"
    on_failure = continue
  }
}

resource "aws_ssm_document" "SSM-SessionManagerRunShell" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"
  depends_on      = [null_resource.cleanupexistingSSM-SessionManagerRunShell]
  content         = <<CONTENT
{
  "schemaVersion": "1.0",
  "description": "Document to hold regional settings for Session Manager",
  "sessionType": "Standard_Stream",
  "inputs": {
    "s3BucketName": "${local.SessionManagerS3LoggingBucketName}",
    "s3KeyPrefix": "${data.aws_caller_identity.current.account_id}",
    "s3EncryptionEnabled": true,
    "cloudWatchLogGroupName": "",
    "cloudWatchEncryptionEnabled": true,
    "cloudWatchStreamingEnabled": true,
    "idleSessionTimeout": "15",
    "kmsKeyId": "${local.SessionManagerKeyArn}",
    "runAsEnabled": false,
    "runAsDefaultUser": "",
    "shellProfile": {
      "windows": "",
      "linux": ""
    }
  }
}
CONTENT
}

data "aws_iam_policy_document" "ConsoleSSMSessionTester" {

  statement {

    sid    = "CreateDatakeysForSSMSessionEncryption"
    effect = "Allow"

    actions = [
      "kms:GenerateDataKey",
    ]

    resources = [
      local.SessionManagerKeyArn,
    ]
    # When Systems Manager Session Manager sessions are created additional metadata referred to as EncryptionContext is generated.
    # Since it can expected that this information to be present in all StartSession requests requiring those fields to be
    # present constrains the use of the KMS key.
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:aws:ssm:SessionId"
      values = [
        "false"
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:ssm:TargetId"
      values = [
        "i-*"
      ]
    }
  }

  statement {

    # Standard read permissions for the EC2 IAM and SSM service and the ability to use Session Manager.

    sid = "ReadPermissionsRequiredtoNavigateConsole"

    effect = "Allow"

    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeInstanceCreditSpecifications",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSnapshots",
      "ec2:DescribeSubnets",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications",
      "ec2:DescribeVolumeStatus",
      "ec2:DescribeVpcs",
      "ec2:GetEbsEncryptionByDefault",
      "IAM:ListInstanceProfiles",
      "IAM:ListRoles",
      "kms:ListAliases",
      "ssm:DescribeInstanceInformation",
      "ssm:DescribeSessions",
      "ssm:GetConnectionStatus",
      "ssm:ListAssociations",
      "ssm:StartSession",
    ]

    resources = [
      "*",
    ]
  }

  # This solution overwrites the default Session Document, "SSM-SessionManagerRunShell".
  # This deny statement allows the princcipal to be free to connect to any instance but limits
  # their session document use to the default.  Making session logging compulsory.

  statement {

    sid    = "LimitSessionDocumentUsetoDefaultDocument"
    effect = "Deny"

    actions = [
      "ssm:StartSession",
    ]

    not_resources = [
      "arn:aws:ec2:*:*:instance/*",
      "arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell"
    ]
  }


}

resource "aws_iam_policy" "ConsoleSSMSessionTester" {
  name        = "ConsoleSSMSessionTesterRolePermissions"
  path        = "/common/examples/"
  description = "Permissions for basic EC2 read permissions and the ability to start Systems Manager Sessions"
  policy      = data.aws_iam_policy_document.ConsoleSSMSessionTester.json
}

resource "aws_iam_role" "ConsoleSSMSessionTester" {
  name = "ConsoleSSMSessionTester"
  path = "/common/examples/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      },
    ]
  })

}


resource "aws_iam_role_policy_attachment" "ConsoleSSMSessionTester" {
  role       = aws_iam_role.ConsoleSSMSessionTester.name
  policy_arn = aws_iam_policy.ConsoleSSMSessionTester.arn
}


