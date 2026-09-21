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


def build_policy(admin_role_arn, parent_role_arn, pcr0, key_arn=None):
    """Use one policy for both CreateKey and an explicitly named existing key."""
    admin = ROLE_ARN.fullmatch(admin_role_arn)
    parent = ROLE_ARN.fullmatch(parent_role_arn)
    if not admin or not parent:
        raise ValueError("principals must be complete commercial-partition IAM role ARNs, without wildcards")
    if admin.group(1) != parent.group(1):
        raise ValueError("administrator and parent role must be in the same AWS account")
    if admin_role_arn == parent_role_arn:
        raise ValueError("administrator and parent roles must be different")
    if key_arn is not None:
        key = KEY_ARN.fullmatch(key_arn)
        if not key or key.group(1).startswith(("cn-", "us-gov-")):
            raise ValueError("key ARN must identify a key in the commercial aws partition; aliases are not accepted")
        if key.group(2) != admin.group(1):
            raise ValueError("key, administrator, and parent role must be in the same AWS account")
    if not re.fullmatch(r"[0-9a-fA-F]{96}", pcr0) or int(pcr0, 16) == 0:
        raise ValueError("PCR0 must be exactly 96 hexadecimal characters and must not be all zero (debug mode)")
    pcr0 = pcr0.lower()

    # In a KMS *key policy*, Resource '*' means only the key to which it is
    # attached. No Allow statement has a wildcard principal or kms:* action.
    return {
        "Version": "2012-10-17",
        "Id": "sapio-tee" if key_arn is None else "sapio-tee:" + key_arn,
        "Statement": [
            {
                "Sid": "SeparateKeyAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": admin_role_arn},
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
                "Principal": {"AWS": parent_role_arn},
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform", action="store_true", help="read a Terraform external query and emit a CreateKey policy")
    parser.add_argument("--key-arn", help="full ARN of the existing P256 KEY_AGREEMENT key")
    parser.add_argument("--admin-role-arn", help="separate same-account key administrator role")
    parser.add_argument("--parent-role-arn", help="same-account EC2 instance-profile IAM role (not profile ARN)")
    parser.add_argument("--pcr0", help="independently measured, nonzero 96-hex SHA384 PCR0")
    parser.add_argument("--output", default="-", help="new output file; default stdout; existing files are never overwritten")
    args = parser.parse_args()
    if args.terraform:
        if any((args.key_arn, args.admin_role_arn, args.parent_role_arn, args.pcr0)) or args.output != "-":
            parser.error("--terraform reads only its JSON query; do not combine it with other options")
        try:
            query = json.load(sys.stdin)
            fields = {"admin_role_arn", "parent_role_arn", "pcr0"}
            if not isinstance(query, dict) or set(query) != fields or not all(isinstance(v, str) for v in query.values()):
                raise ValueError("query must contain only string admin_role_arn, parent_role_arn and pcr0")
            policy = build_policy(**query)
        except (ValueError, OSError) as error:
            parser.error(str(error))
        # The ARN does not exist until CreateKey; Resource '*' already scopes
        # this policy to that key. No temporary broad bootstrap policy is used.
        sys.stdout.write(json.dumps({"policy": json.dumps(policy)}) + "\n")
        return
    if not all((args.key_arn, args.admin_role_arn, args.parent_role_arn, args.pcr0)):
        parser.error("--key-arn, --admin-role-arn, --parent-role-arn and --pcr0 are required")
    try:
        policy = build_policy(args.admin_role_arn, args.parent_role_arn, args.pcr0, args.key_arn)
    except ValueError as error:
        parser.error(str(error))
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
