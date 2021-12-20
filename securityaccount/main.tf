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

locals {

  # It is common practice to "prefix" the naming of an S3 bucket with the name of the company or business group which it belongs to make organization of resources easier.
  # Such examples could be "companyname", companyname-businessunitname, or a stock abbreviation.
  ResourceNamingPrefix = "widget-inc"


  # INPUT THE FULL ARN of a role permitted to review Systems Manager Session Manager logs. 
  LogReviewRoleArn = "arn:aws:iam::12345689012:role/auditrolename"

  # This variable requires no inputs unless you wish to replace the default naming pattern.
  SessionManagerS3LoggingBucketName = "${local.ResourceNamingPrefix}-ssmsessionlogging-${data.aws_region.current.name}" #An interpolated value which will generate a name for the S3 bucket.
}

data "aws_iam_policy_document" "SessionManagerKey" {

  # When Systems Manager Session Manager sessions are created additional metadata referred to as EncryptionContext is generated.
  # Since it can expected that this information to be present in requests to generate and decrypt the data key encrypting the session this condition
  # can be used to constrain permissions to use the KMS key for either purpose.

  statement {
    sid    = "Session Encryption Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
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
    sid    = "Bucket Object Encryption Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
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
    sid    = "BucketKey Enabled Bucket Object Encryption Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
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


  statement {
    sid    = "Key Administration Permissions for Pipeline Entity"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:*Grant",
      "kms:CancelKeyDeletion",
      "kms:CreateAlias",
      "kms:DeleteAlias",
      "kms:DescribeKey",
      "kms:DisableKey",
      "kms:EnableKeyRotation",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:List*",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UpdateKeyDescription",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values = [
        data.aws_caller_identity.current.account_id
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values = [
        data.aws_iam_session_context.current.issuer_arn
      ]
    }
  }

  statement {
    sid    = "Object Decrypt Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:Decrypt",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values = [
        data.aws_caller_identity.current.account_id
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values = [
        local.LogReviewRoleArn
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*"
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
  }

  statement {
    sid    = "Bucket Key Enabled Object Decrypt Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:Decrypt",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values = [
        data.aws_caller_identity.current.account_id
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values = [
        local.LogReviewRoleArn
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "s3.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
  }


  statement {
    sid    = "Key Holding Account General Read Permission"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:List*",
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values = [
        data.aws_caller_identity.current.account_id
      ]
    }
  }

  statement {
    sid    = "Access Analyzer Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:List*"
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:InvokedBy"
      values   = ["access-analyzer.amazonaws.com"]
    }

  }

  statement {
    sid    = "Allow Macie To Use Key"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
    ]

    resources = [
      "*",
    ]

    condition {
  test     = "StringEquals"
  variable = "aws:PrincipalArn"
  values = [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
  ]
}
 }

  # The BypassPolicyLockoutSafetyCheck is a dangerous option to use when updating a KMS key as it may result in a key no principal can access.
  statement {
    sid    = "Deny Safety Lockout Bypass"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:PutKeyPolicy"
    ]

    resources = [
      "*",
    ]
    condition {
      test     = "Bool"
      variable = "kms:BypassPolicyLockoutSafetyCheck"
      values   = ["true"]
    }
  }


  #OPTIONAL Permissions for AWS Config to perform detections against key example
  #     statement {
  #     sid    = "AWS Config Permissions"
  #     effect = "Allow"
  #     principals {
  #       type        = "AWS"
  #       identifiers = ["*"]
  #     }
  #     actions = [
  #       "kms:DescribeKey",
  #       "kms:GetKeyPolicy",
  #       "kms:List*"
  #     ]

  #     resources = [
  #       "*",
  #     ]
  #     condition {
  #       test     = "StringEquals"
  #       variable = "aws:PrincipalArn"
  #       values = [
  #         ##ARNOFCONFIGRECORDERROLE##
  #       ]
  #     }
  #   }

}

resource "aws_kms_key" "SessionManager" {
  description                        = "Key to Encrypt Systems Manager Session Manager Sessions and Encrypt logs at rest in S3"
  deletion_window_in_days            = 30
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  policy                             = data.aws_iam_policy_document.SessionManagerKey.json
  bypass_policy_lockout_safety_check = false
  is_enabled                         = true
  enable_key_rotation                = true

}

resource "aws_kms_alias" "SessionManager" {
  name          = "alias/SessionKey"
  target_key_id = aws_kms_key.SessionManager.key_id
}

data "aws_iam_policy_document" "SessionManagerS3Bucket" {

  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:GetEncryptionConfiguration",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/$${aws:PrincipalAccount}/*",
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
  }

  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*"
    ]
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }

  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*"
    ]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.SessionManager.arn]
    }
  }


  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:PutObject",
    ]

    not_resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*.log"
    ]
  }

  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*",
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*",
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}",
    ]

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }


  statement {
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:BypassGovernanceRetention",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:DeleteBucketWebsite",
      "s3:PutAccelerateConfiguration",
      "s3:PutAnalyticsConfiguration",
      "s3:PutBucketAcl",
      "s3:PutBucketCORS",
      "s3:PutBucketLogging",
      "s3:PutBucketNotification",
      "s3:PutBucketOwnershipControls",
      "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketRequestPayment",
      "s3:PutBucketVersioning",
      "s3:PutBucketWebsite",
      "s3:PutEncryptionConfiguration",
      "s3:PutInventoryConfiguration",
      "s3:PutLifecycleConfiguration",
      "s3:PutMetricsConfiguration",
      "s3:PutReplicationConfiguration",

    ]

    resources = [
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}/*",
      "arn:aws:s3:::${local.SessionManagerS3LoggingBucketName}",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        data.aws_caller_identity.current.account_id
      ]
    }
  }


}


resource "aws_s3_bucket" "SessionManagerS3Logging" {
  bucket = local.SessionManagerS3LoggingBucketName
  acl    = "private"

  versioning {
    enabled = true
  }
    #TODO 
  #   logging {
  #   target_bucket = "Putloggingbucketnamehere"
  #   target_prefix = "${local.SessionManagerS3LoggingBucketName}/"
  # }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.SessionManager.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_policy" "SessionManagerS3Logging" {
  bucket = aws_s3_bucket.SessionManagerS3Logging.id
  policy = data.aws_iam_policy_document.SessionManagerS3Bucket.json
}

resource "aws_s3_bucket_public_access_block" "SessionManagerS3Logging" {
  bucket                  = aws_s3_bucket.SessionManagerS3Logging.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "SessionManagerS3Logging" {
  bucket = aws_s3_bucket.SessionManagerS3Logging.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

output "SessionManagerKeyArn" {
  value = aws_kms_key.SessionManager.arn
}

output "SessionManagerS3LoggingBucketName" {
  value = aws_s3_bucket.SessionManagerS3Logging.id
}

output "SessionManagerS3LoggingBucketNameAccountId" {
  value = data.aws_caller_identity.current.account_id
}
