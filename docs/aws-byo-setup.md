# AWS setup for the first real cloud round-trip

This is the minimum AWS setup needed for the local Mac runtime to prove the
remote -> local -> remote loop with a bring-your-own AWS subscription.

The important constraint: the capture host must expose **KVM on arm64**. A
normal Graviton EC2 VM is not enough. Use a Graviton **bare-metal** instance
type in a region where your account has quota, or another arm64 cloud host that
exposes `/dev/kvm`.

## 1. AWS account prerequisites

- An AWS account with billing enabled.
- A region with Graviton bare-metal capacity, for example a `*.metal` Graviton
  family where available.
- An EC2 quota that allows launching that bare-metal instance type.
- A VPC/subnet with outbound internet access.
- Either:
    - SSH access via a key pair, or
    - AWS Systems Manager Session Manager access.

## Cost expectation

Just setting up the IAM profile, an empty private S3 bucket, and local AWS CLI
configuration should be effectively zero-cost.

Standing still can still cost money if any billable infrastructure is left
allocated:

- **Running Graviton bare-metal capture host:** expect roughly \*\*$2.30-$2.70 per
  hour\*\* in `us-east-1`-class regions for `c7g.metal` / `m7g.metal`-class
  instances. This is the expensive part; terminate it when not actively
  capturing.
- **Stopped EC2 instance:** no compute charge, but attached EBS volumes still
  charge.
- **EBS gp3 volumes:** roughly **$0.08 per GB-month**. A 100 GiB volume is about
  **$8/month** while it exists.
- **S3 Standard artifacts:** roughly **$0.023 per GB-month**. A 20 GiB snapshot
  bundle is about **$0.46/month** before request/transfer costs.
- **NAT Gateway:** avoid for this project if possible. It costs roughly
  **$0.045/hour** plus data processing, or about **$32/month** even while idle.
- **Public IPv4 / Elastic IP:** AWS charges for public IPv4 addresses; expect
  roughly **$0.005/hour** per address, or about **$3.60/month**.

The intended cost posture for the first milestone is: keep only the private S3
bucket and maybe small retained artifacts between runs; launch the bare-metal
host only for capture; then terminate the host and delete temporary EBS/network
resources during cleanup.

## 2. Local tools

Install and configure:

```bash
brew install awscli
aws configure sso
# or: aws configure --profile chm-aws
```

Useful environment:

```bash
export AWS_PROFILE=chm-aws
export AWS_REGION=us-east-1
```

## 3. IAM permissions for the local app

The first version is local-managed: the Mac app/CLI uses your AWS credentials
directly. There is no hosted control plane yet.

Create a role/user/profile for the local runtime with permission to:

- describe, launch, stop, start and terminate EC2 instances;
- create, attach, detach and delete EBS volumes used for test disks;
- read/write a dedicated S3 bucket for snapshot bundles;
- use SSM if you want shell access without inbound SSH;
- pass only the specific EC2 instance role used by the capture host.

Keep this scoped to a dedicated resource prefix such as:

- instance tag: `Project=cloud-hypervisor-mac`
- S3 bucket/prefix: `s3://<your-bucket>/cloud-hypervisor-mac/`
- IAM role name: `cloud-hypervisor-mac-capture-role`

## 4. S3 artifact bucket

Create one private bucket for handoff artifacts:

```bash
aws s3 mb s3://<your-chm-snapshot-bucket>
aws s3api put-public-access-block \
  --bucket <your-chm-snapshot-bucket> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

The local runtime will use this bucket for:

- captured cloud-hypervisor snapshot directories;
- disk/overlay artifacts needed to rehydrate locally;
- logs and proof files from the remote capture worker.

## 5. Capture host shape

Start with:

- Ubuntu arm64 AMI;
- Graviton bare-metal instance;
- one root EBS volume;
- optional extra EBS volume for guest disk images;
- security group with SSH from your IP only, or no inbound access if using SSM.

On the host we need:

```bash
sudo apt-get update
sudo apt-get install -y build-essential git curl jq qemu-utils
test -e /dev/kvm
```

If `/dev/kvm` is missing, the instance is not suitable for this milestone.

## 6. Snapshot compatibility requirement

For macOS Hypervisor.framework today, do **not** capture a stock ITS/LPI-routed
arm64 cloud-hypervisor snapshot. Apple's managed GIC cannot deliver LPIs to a
normal EL1 guest.

The capture must use the project-supported **GICv2M/message-SPI** path so virtio
completion interrupts are deliverable locally through `hv_gic_send_msi` and the
proven 1-of-N SPI route.

## 7. First manual proof loop

The first milestone should prove this manually before the app automates it:

1. Local Mac launches or connects to the AWS capture host.
2. Remote host builds/runs the compatible cloud-hypervisor capture workload.
3. Remote host creates a snapshot bundle.
4. Remote host uploads the bundle to S3.
5. Local Mac downloads the bundle.
6. `chm run <snapshot>` rehydrates it locally.
7. Local Mac uploads any changed overlay/proof artifacts back to S3.
8. Remote host consumes those artifacts for the return leg.

## 8. Cleanup expectation

The local runtime should always be able to tear down what it created:

- terminate capture instances;
- delete temporary volumes;
- delete temporary security groups if it created them;
- keep or expire S3 artifacts according to a user-selected retention policy.

Until the remote control plane exists, the local app owns orchestration and
cleanup.

## 9. Destructive cleanup script

Every resource created by the AWS prototype must be tagged:

```text
Project=cloud-hypervisor-mac
```

That tag is the blast-radius guard for the cleanup script. The script defaults
to dry-run and only deletes when both `--execute` and `--yes` are present.

Dry-run:

```bash
scripts/aws-cleanup-chm.sh \
  --profile chm-aws \
  --region us-east-1 \
  --project cloud-hypervisor-mac \
  --bucket <your-chm-snapshot-bucket>
```

Destructive cleanup:

```bash
scripts/aws-cleanup-chm.sh \
  --profile chm-aws \
  --region us-east-1 \
  --project cloud-hypervisor-mac \
  --bucket <your-chm-snapshot-bucket> \
  --execute \
  --yes
```

Delete the bucket too:

```bash
scripts/aws-cleanup-chm.sh \
  --profile chm-aws \
  --region us-east-1 \
  --project cloud-hypervisor-mac \
  --bucket <your-chm-snapshot-bucket> \
  --delete-bucket \
  --execute \
  --yes
```

The script targets:

- tagged EC2 instances;
- tagged NAT gateways;
- tagged Elastic IPs;
- tagged available EBS volumes;
- tagged EBS snapshots;
- tagged non-default security groups;
- tagged EC2 key pairs;
- optional S3 prefix/bucket artifacts.

It intentionally does **not** delete IAM users, roles, policies or instance
profiles. Remove those manually after confirming nothing else uses them.

If the script terminates instances, re-run it after a few minutes to catch EBS
volumes that only become `available` after termination and detach completes.
