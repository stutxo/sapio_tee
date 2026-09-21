#!/usr/bin/env python3
"""Wait for this Terraform instance's SSM command, not an association summary."""

import json
import os
import subprocess
import sys
import time

from initialize import validate_identity, validate_settings


def main():
    try:
        region = os.environ["AWS_REGION"]
        instance = os.environ["SAPIO_INSTANCE_ID"]
        settings = json.loads(os.environ["SAPIO_SETUP_JSON"])
        validate_settings(settings)
        deadline = time.monotonic() + 1200

        def remaining():
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise ValueError("timed out waiting for the instance's initialized signer")
            return seconds

        def aws(*arguments, pending_invocation=False):
            result = subprocess.run(
                ["aws", "--region", region, "--no-cli-pager", "--output", "json", "ssm", *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=min(60, remaining()), check=False,
            )
            if result.returncode:
                # SSM documents that command invocation records are eventually consistent.
                if pending_invocation and "(InvocationDoesNotExist)" in result.stderr:
                    return {"Status": "Pending"}
                raise ValueError(result.stderr.strip() or "AWS CLI failed")
            return json.loads(result.stdout)

        print(f"Waiting for Systems Manager on {instance}...", flush=True)
        while True:
            nodes = aws("describe-instance-information", "--filters", f"Key=InstanceIds,Values={instance}")
            if any(node.get("InstanceId") == instance and node.get("PingStatus") == "Online"
                   for node in nodes["InstanceInformationList"]):
                break
            time.sleep(min(5, remaining()))

        commands = [
            "set -eu",
            "cloud-init status --wait >&2",
            "systemctl is-active --quiet sapio-tee.service",
            "python3 /opt/sapio-tee/deploy/initialize.py --settings /opt/sapio-tee/setup.json --timeout 30",
        ]
        command = aws(
            "send-command", "--document-name", "AWS-RunShellScript", "--instance-ids", instance,
            "--parameters", json.dumps({"commands": commands, "executionTimeout": ["900"]}),
            "--comment", "Sapio Terraform deployment readiness",
        )["Command"]["CommandId"]
        while True:
            invocation = aws("get-command-invocation", "--command-id", command,
                             "--instance-id", instance, pending_invocation=True)
            status = invocation["Status"]
            if status == "Success":
                if invocation.get("ResponseCode") != 0:
                    raise ValueError("SSM command succeeded without a zero process exit status")
                identity = validate_identity(invocation["StandardOutputContent"], settings)
                print(json.dumps(identity, separators=(",", ":")))
                return 0
            if status not in ("Pending", "InProgress", "Delayed"):
                raise ValueError(f"SSM readiness command {command}: {status}: "
                                 + invocation.get("StandardErrorContent", ""))
            time.sleep(min(5, remaining()))
    except (KeyError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"deployment readiness failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
