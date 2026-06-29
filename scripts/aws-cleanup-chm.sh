#!/usr/bin/env bash
#
# Destructive AWS cleanup for cloud-hypervisor-mac BYO-subscription experiments.
#
# Default mode is dry-run. To actually delete resources, pass BOTH:
#
#   --execute --yes
#
# The script is intentionally tag-scoped. It only targets EC2 resources tagged
# with Project=<value> (default: cloud-hypervisor-mac). S3 cleanup is opt-in via
# --bucket and --delete-bucket.

set -euo pipefail

PROJECT_TAG="cloud-hypervisor-mac"
PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_REGION:-}"
BUCKET=""
PREFIX="cloud-hypervisor-mac/"
EXECUTE=0
YES=0
WAIT=1

usage() {
    cat <<'EOF'
Usage:
  scripts/aws-cleanup-chm.sh [options]

Dry-run first:
  scripts/aws-cleanup-chm.sh --profile chm-aws --region us-east-1

Actually delete tagged resources:
  scripts/aws-cleanup-chm.sh --profile chm-aws --region us-east-1 --execute --yes

Also delete S3 artifacts:
  scripts/aws-cleanup-chm.sh --profile chm-aws --region us-east-1 \
    --bucket my-chm-bucket --prefix cloud-hypervisor-mac/ --execute --yes

Delete the bucket itself too:
  scripts/aws-cleanup-chm.sh --profile chm-aws --region us-east-1 \
    --bucket my-chm-bucket --delete-bucket --execute --yes

Options:
  --profile NAME       AWS CLI profile to use.
  --region REGION     AWS region to clean.
  --project VALUE     Tag value for Project=<VALUE>. Default: cloud-hypervisor-mac.
  --bucket NAME       Optional S3 bucket to empty under --prefix.
  --prefix PREFIX     S3 prefix to delete. Default: cloud-hypervisor-mac/.
  --delete-bucket     Delete --bucket after emptying the prefix/bucket.
  --no-wait           Do not wait for EC2 instance/NAT gateway termination.
  --execute           Perform deletion. Without this, the script only prints.
  --yes               Required together with --execute.
  -h, --help          Show this help.

This script deletes resources created for the BYO AWS milestone. It does not
delete IAM users, roles, policies, or instance profiles; remove those manually
after confirming nothing else uses them.
EOF
}

DELETE_BUCKET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --project)
            PROJECT_TAG="$2"
            shift 2
            ;;
        --bucket)
            BUCKET="$2"
            shift 2
            ;;
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --delete-bucket)
            DELETE_BUCKET=1
            shift
            ;;
        --no-wait)
            WAIT=0
            shift
            ;;
        --execute)
            EXECUTE=1
            shift
            ;;
        --yes)
            YES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$REGION" ]]; then
    echo "error: --region or AWS_REGION is required" >&2
    exit 2
fi

if [[ "$EXECUTE" -eq 1 && "$YES" -ne 1 ]]; then
    echo "error: --execute requires --yes" >&2
    exit 2
fi

AWS=(aws --region "$REGION")
if [[ -n "$PROFILE" ]]; then
    AWS+=(--profile "$PROFILE")
fi

run() {
    echo "+ ${AWS[*]} $*"
    if [[ "$EXECUTE" -eq 1 ]]; then
        "${AWS[@]}" "$@"
    fi
}

query_text() {
    "${AWS[@]}" "$@" --output text
}

read_words() {
    local out="$1"
    if [[ -z "$out" || "$out" == "None" ]]; then
        return 0
    fi
    # shellcheck disable=SC2206
    WORDS=($out)
}

echo "AWS cleanup for Project=$PROJECT_TAG in region $REGION"
if [[ "$EXECUTE" -eq 0 ]]; then
    echo "Mode: DRY RUN. Re-run with --execute --yes to delete."
else
    echo "Mode: EXECUTE. Deleting matching resources."
fi

echo
echo "== EC2 instances =="
instances="$(query_text ec2 describe-instances \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId')"
WORDS=()
read_words "$instances"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    run ec2 terminate-instances --instance-ids "${WORDS[@]}"
    if [[ "$EXECUTE" -eq 1 && "$WAIT" -eq 1 ]]; then
        run ec2 wait instance-terminated --instance-ids "${WORDS[@]}"
    fi
else
    echo "No matching non-terminated instances."
fi

echo
echo "== NAT gateways =="
nat_gateways="$(query_text ec2 describe-nat-gateways \
    --filter "Name=tag:Project,Values=$PROJECT_TAG" \
             "Name=state,Values=pending,available" \
    --query 'NatGateways[].NatGatewayId')"
WORDS=()
read_words "$nat_gateways"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for nat in "${WORDS[@]}"; do
        run ec2 delete-nat-gateway --nat-gateway-id "$nat"
    done
    if [[ "$EXECUTE" -eq 1 && "$WAIT" -eq 1 ]]; then
        for nat in "${WORDS[@]}"; do
            run ec2 wait nat-gateway-deleted --nat-gateway-ids "$nat"
        done
    fi
else
    echo "No matching NAT gateways."
fi

echo
echo "== Elastic IP addresses =="
allocations="$(query_text ec2 describe-addresses \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
    --query 'Addresses[].AllocationId')"
WORDS=()
read_words "$allocations"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for allocation in "${WORDS[@]}"; do
        association="$(query_text ec2 describe-addresses \
            --allocation-ids "$allocation" \
            --query 'Addresses[0].AssociationId' || true)"
        if [[ -n "$association" && "$association" != "None" ]]; then
            run ec2 disassociate-address --association-id "$association"
        fi
        run ec2 release-address --allocation-id "$allocation"
    done
else
    echo "No matching Elastic IP addresses."
fi

echo
echo "== EBS volumes =="
volumes="$(query_text ec2 describe-volumes \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
              "Name=status,Values=available" \
    --query 'Volumes[].VolumeId')"
WORDS=()
read_words "$volumes"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for volume in "${WORDS[@]}"; do
        run ec2 delete-volume --volume-id "$volume"
    done
else
    echo "No matching available volumes. If instances were just terminated, re-run after EBS detach completes."
fi

echo
echo "== EBS snapshots =="
snapshots="$(query_text ec2 describe-snapshots \
    --owner-ids self \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
    --query 'Snapshots[].SnapshotId')"
WORDS=()
read_words "$snapshots"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for snapshot in "${WORDS[@]}"; do
        run ec2 delete-snapshot --snapshot-id "$snapshot"
    done
else
    echo "No matching EBS snapshots."
fi

echo
echo "== Security groups =="
security_groups="$(query_text ec2 describe-security-groups \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
    --query 'SecurityGroups[?GroupName!=`default`].GroupId')"
WORDS=()
read_words "$security_groups"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for sg in "${WORDS[@]}"; do
        run ec2 delete-security-group --group-id "$sg" || true
    done
else
    echo "No matching non-default security groups."
fi

echo
echo "== Key pairs =="
key_pairs="$(query_text ec2 describe-key-pairs \
    --filters "Name=tag:Project,Values=$PROJECT_TAG" \
    --query 'KeyPairs[].KeyName')"
WORDS=()
read_words "$key_pairs"
if [[ "${#WORDS[@]}" -gt 0 ]]; then
    for key in "${WORDS[@]}"; do
        run ec2 delete-key-pair --key-name "$key"
    done
else
    echo "No matching EC2 key pairs."
fi

if [[ -n "$BUCKET" ]]; then
    echo
    echo "== S3 artifacts =="
    if [[ "$DELETE_BUCKET" -eq 1 ]]; then
        echo "Target bucket: s3://$BUCKET (entire bucket will be emptied and deleted)"
        run s3 rm "s3://$BUCKET" --recursive
        run s3 rb "s3://$BUCKET"
    else
        echo "Target prefix: s3://$BUCKET/$PREFIX"
        run s3 rm "s3://$BUCKET/$PREFIX" --recursive
    fi
else
    echo
    echo "== S3 artifacts =="
    echo "No --bucket supplied; S3 cleanup skipped."
fi

echo
echo "Cleanup pass complete."
if [[ "$EXECUTE" -eq 0 ]]; then
    echo "Dry-run only. Nothing was deleted."
fi
