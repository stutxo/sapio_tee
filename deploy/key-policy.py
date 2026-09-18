#!/usr/bin/env python3
"""Generate a complete KMS key policy locally; never call AWS or alter a key."""

import argparse
import json
import re
import sys


PCR_KEY = "kms:RecipientAttestation:PCR0"
KEY_ARN = re.compile(
    r"arn:aws:kms:([a-z]{2}(?:-[a-z]+)+-[0-9]+):([0-9]{12}):key/"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})"
)
ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@/-]+)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-arn", required=True, help="full ARN of the existing P256 KEY_AGREEMENT key")
    parser.add_argument("--admin-role-arn", required=True, help="separate same-account key administrator role")
    parser.add_argument("--parent-role-arn", required=True, help="same-account EC2 instance-profile IAM role (not profile ARN)")
    parser.add_argument("--pcr0", required=True, help="independently measured, nonzero 96-hex SHA384 PCR0")
    parser.add_argument("--output", default="-", help="new output file; default stdout; existing files are never overwritten")
    args = parser.parse_args()

    key = KEY_ARN.fullmatch(args.key_arn)
    admin = ROLE_ARN.fullmatch(args.admin_role_arn)
    parent = ROLE_ARN.fullmatch(args.parent_role_arn)
    if not key or key.group(1).startswith(("cn-", "us-gov-")):
        parser.error("key ARN must identify a key in the commercial aws partition; aliases are not accepted")
    if not admin or not parent:
        parser.error("principals must be complete commercial-partition IAM role ARNs, without wildcards")
    if admin.group(1) != key.group(2) or parent.group(1) != key.group(2):
        parser.error("key, administrator, and parent role must be in the same AWS account")
    if args.admin_role_arn == args.parent_role_arn:
        parser.error("administrator and parent roles must be different")
    if not re.fullmatch(r"[0-9a-fA-F]{96}", args.pcr0) or int(args.pcr0, 16) == 0:
        parser.error("PCR0 must be exactly 96 hexadecimal characters and must not be all zero (debug mode)")
    pcr0 = args.pcr0.lower()

    # In a KMS *key policy*, Resource '*' means only the key to which it is
    # attached. No Allow statement has a wildcard principal or kms:* action.
    policy = {
        "Version": "2012-10-17",
        "Id": "sapio-tee:" + args.key_arn,
        "Statement": [
            {
                "Sid": "SeparateKeyAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": args.admin_role_arn},
                "Action": [
                    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListKeyPolicies",
                    "kms:PutKeyPolicy", "kms:EnableKey", "kms:DisableKey",
                    "kms:UpdateKeyDescription", "kms:TagResource", "kms:UntagResource",
                    "kms:ListResourceTags", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
                ],
                "Resource": "*",
            },
            {
                "Sid": "ParentMayDeriveOnlyForMeasuredEnclave",
                "Effect": "Allow",
                "Principal": {"AWS": args.parent_role_arn},
                "Action": "kms:DeriveSharedSecret",
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {PCR_KEY: pcr0},
                    "StringEquals": {
                        "kms:KeyAgreementAlgorithm": "ECDH",
                        "kms:KeySpec": "ECC_NIST_P256",
                        "kms:KeyUsage": "KEY_AGREEMENT",
                    },
                },
            },
            {
                "Sid": "DenyDerivationWithoutRecipientAttestation",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kms:DeriveSharedSecret",
                "Resource": "*",
                "Condition": {"Null": {PCR_KEY: "true"}},
            },
            {
                "Sid": "DenyDerivationOutsideMeasuredEnclave",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kms:DeriveSharedSecret",
                "Resource": "*",
                "Condition": {"StringNotEqualsIgnoreCase": {PCR_KEY: pcr0}},
            },
        ],
    }
    encoded = json.dumps(policy, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(encoded)
    else:
        try:
            with open(args.output, "x", encoding="utf-8") as destination:
                destination.write(encoded)
        except OSError as error:
            parser.exit(1, f"cannot write policy: {error}\n")


if __name__ == "__main__":
    main()
