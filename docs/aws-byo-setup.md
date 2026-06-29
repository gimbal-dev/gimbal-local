# AWS setup for the first real cloud round-trip

This is the beginner-safe AWS checklist for proving:

```text
AWS arm64 KVM host -> snapshot bundle -> local Mac chm -> return artifacts -> AWS
```

The goal is **not** to build a hosted control plane yet. The Mac stays in charge
and uses your AWS subscription directly.

## Read this first

### The one hard technical requirement

The remote capture machine must expose **arm64 KVM**:

```bash
test -e /dev/kvm
```

A normal Graviton EC2 VM usually will **not** work because it does not expose
nested KVM. For the real AWS proof, start with a **Graviton bare-metal**
instance type, for example a `*.metal` Graviton family in a region where your
account has quota.

### The one hard cost rule

Do **not** leave the bare-metal instance running.

The intended pattern is:

1. Launch capture host.
2. Capture snapshot.
3. Upload snapshot to S3.
4. Terminate capture host.
5. Rehydrate locally on the Mac.

## What costs money?

Setup-only should be close to zero cost:

- IAM profile/role: no direct cost.
- Local AWS CLI config: no cost.
- Empty private S3 bucket: effectively no cost.

Standing still can cost money if resources are left allocated:

| Resource | Cost shape | What to do |
| --- | --- | --- |
| Running Graviton bare-metal EC2 | Roughly `$2.30-$2.70/hour` for `c7g.metal` / `m7g.metal` class instances in us-east-1-style regions | Terminate when not capturing |
| Stopped EC2 | No compute charge, but attached EBS still bills | Prefer terminate, not stop |
| EBS gp3 volume | Roughly `$0.08/GB-month`; 100 GiB is about `$8/month` | Delete temporary volumes |
| S3 Standard | Roughly `$0.023/GB-month`; 20 GiB is about `$0.46/month` | Keep only wanted snapshot bundles |
| NAT Gateway | Roughly `$0.045/hour` plus data, about `$32/month` idle | Avoid for this prototype |
| Public IPv4 / Elastic IP | Roughly `$0.005/hour`, about `$3.60/month` | Release when done |

## Naming and tagging rule

Everything we create for this project should use:

```text
Project=cloud-hypervisor-mac
```

This tag lets the cleanup script find and delete project resources without
touching unrelated AWS resources.

Use these names unless you have a reason not to:

```text
AWS profile:       chm-aws
Project tag:       cloud-hypervisor-mac
S3 prefix:         cloud-hypervisor-mac/
EC2 role name:     cloud-hypervisor-mac-capture-role
```

## Step 1: Install the AWS CLI on your Mac

```bash
brew install awscli
aws --version
```

Pick a region. Start with whatever region has Graviton bare-metal capacity and
quota for your account:

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=chm-aws
```

## Step 2: Login to AWS from your Mac

For a personal AWS account, do **not** start with SSO. SSO / IAM Identity
Center is mostly for companies or multi-account setups. It is fine later, but it
is unnecessary ceremony for this prototype.

Do this instead:

1. Log in to the AWS Console with your root user.
2. Turn on MFA for the root user if AWS prompts you to.
3. Create one IAM user named `cloud-hypervisor-mac-cli`.
4. Give that IAM user temporary `AdministratorAccess` for this prototype.
5. Create an access key for that IAM user.
6. Store that access key only in your local Mac AWS CLI profile.
7. Stop using the root user for day-to-day commands.

### Create the IAM user in the AWS Console

In the AWS Console:

1. Search for **IAM** in the top search bar.
2. Open **IAM**.
3. Click **Users** in the left sidebar.
4. Click **Create user**.
5. Enter this user name:

```text
cloud-hypervisor-mac-cli
```

6. Leave **Provide user access to the AWS Management Console** unchecked.
   This user is only for local CLI access.
7. Click **Next**.
8. Select **Attach policies directly**.
9. Search for `AdministratorAccess`.
10. Tick the checkbox next to **AdministratorAccess**.
11. Click **Next**.
12. Click **Create user**.

This is intentionally broad for the first manual proof. The account should be
treated as a temporary sandbox, and cleanup must be run after experiments.

### Create the access key

Still in IAM:

1. Click the new `cloud-hypervisor-mac-cli` user.
2. Open the **Security credentials** tab.
3. Scroll to **Access keys**.
4. Click **Create access key**.
5. Choose **Command Line Interface (CLI)**.
6. Tick the confirmation checkbox.
7. Set the description to:

```text
cloud-hypervisor-mac local CLI
```

8. Click **Create access key**.
9. Copy the **Access key** and **Secret access key**, or download the `.csv`.

The secret access key is shown only once. If you lose it, delete that key and
create a new one.

Then configure the local profile:

```bash
aws configure --profile chm-aws
```

It will ask for:

```text
AWS Access Key ID:     <paste IAM user's access key id>
AWS Secret Access Key: <paste IAM user's secret access key>
Default region name:   us-east-1
Default output format: json
```

If the AWS CLI asks for an **SSO start URL**, stop. You are in the wrong
configure flow for this guide. Press `Ctrl+C` and use the non-interactive setup
below instead:

```bash
aws configure set aws_access_key_id "<paste IAM user's access key id>" \
  --profile chm-aws
aws configure set aws_secret_access_key "<paste IAM user's secret access key>" \
  --profile chm-aws
aws configure set region "$AWS_REGION" \
  --profile chm-aws
aws configure set output json \
  --profile chm-aws
```

If you already half-configured SSO for this profile and later commands still try
SSO, remove the bad profile block from your local AWS config:

```bash
open -e ~/.aws/config
```

Delete the whole block that starts with `[profile chm-aws]`, save the file, and
then run the `aws configure set ... --profile chm-aws` commands above again.

Do **not** create access keys for the root user. If you accidentally do, delete
them and create IAM-user keys instead.

Only use this SSO path if you deliberately set up IAM Identity Center:

```bash
aws configure sso --profile chm-aws
aws sso login --profile chm-aws
```

Check the login works:

```bash
aws sts get-caller-identity --profile chm-aws
```

If that command fails, stop here and fix login before creating anything.

## Step 3: Make sure your login has enough permissions

For the first prototype, the AWS identity behind `chm-aws` needs permission to
manage a small set of EC2 and S3 resources.

If you followed Step 2 and attached `AdministratorAccess`, you can continue to
the smoke test below.

That broad permission is not the final desired state. It is a beginner-friendly
bootstrap choice for a personal sandbox account while the workflow is still
manual. The safety rules are:

1. Do not create root access keys.
2. Do not leave the bare-metal instance running.
3. Run cleanup after each experiment.
4. Replace `AdministratorAccess` with a narrow policy before anything becomes
   regular or long-lived.

If you have an AWS admin helping you instead, ask for a temporary sandbox
permission set that can:

- create/delete an S3 bucket and objects;
- create/delete EC2 key pairs;
- create/delete security groups;
- launch/terminate EC2 instances;
- describe EC2 images, subnets, VPCs, instances, volumes and quotas;
- delete project EBS volumes/snapshots;
- release project Elastic IPs if any are created.

Quick permission smoke test:

```bash
aws ec2 describe-vpcs \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --max-items 1 >/dev/null

aws s3api list-buckets \
  --profile chm-aws >/dev/null
```

If either command fails with `AccessDenied`, fix permissions before continuing.

## Step 4: Check whether you have enough EC2 quota

The local runtime now has a read-only preflight command for this section:

```bash
target/debug/chm cloud preflight aws \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --bucket "$CHM_BUCKET" \
  --instance-type c7g.metal
```

Run it after building `chm` with `bash scripts/build-chm.sh`. It does not launch
or create paid resources.

You can persist the common AWS settings locally first, then omit them from later
commands:

```bash
target/debug/chm cloud init aws \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --bucket "$CHM_BUCKET" \
  --prefix cloud-hypervisor-mac/

target/debug/chm cloud preflight aws
```

The config is written only on the Mac, under
`~/Library/Application Support/gimbal-local/cloud-aws.env`.

The quota that normally blocks `c7g.metal` / `m7g.metal` is not named
"Graviton bare metal". It is the regional EC2 On-Demand **vCPU** quota:

```text
Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances
Quota code: L-1216C47A
```

Bare-metal instances in those families still count against this quota by vCPU.
For example, `c7g.metal` commonly needs **64 vCPUs** of quota in the selected
region. If your quota is below the vCPU count of the instance type, launch will
fail.

If the console shows:

```text
Utilization: 0
Applied account-level quota value: 0
AWS default quota value: 5
```

that does **not** mean "request 5". It means the normal default is only \*\*5
vCPUs\*\*, which is fine for small EC2 VMs but still nowhere near enough for a
64-vCPU bare-metal host. Request the number you actually need for the selected
instance type.

Check the quota from your Mac:

```bash
aws service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code L-1216C47A \
  --query 'Quota.{Name:QuotaName,Value:Value}' \
  --output table \
  --profile chm-aws \
  --region "$AWS_REGION"
```

Check how many vCPUs your intended instance type needs:

```bash
export CHM_INSTANCE_TYPE=c7g.metal

aws ec2 describe-instance-types \
  --instance-types "$CHM_INSTANCE_TYPE" \
  --query 'InstanceTypes[0].{InstanceType:InstanceType,Vcpus:VCpuInfo.DefaultVCpus,Arch:ProcessorInfo.SupportedArchitectures}' \
  --output table \
  --profile chm-aws \
  --region "$AWS_REGION"
```

If the quota value is lower than the instance vCPU count, request an increase.
Ask for at least the instance's vCPU count; **128 vCPUs** gives enough room for
one 64-vCPU bare-metal host plus a bit of breathing room.

In the AWS Console:

1. Open **Service Quotas**.
2. Open **AWS services**.
3. Search for **Amazon Elastic Compute Cloud (Amazon EC2)**.
4. Search within EC2 quotas for `L-1216C47A` or **Running On-Demand Standard**.
5. Click the quota.
6. Click **Request increase at account-level**.
7. Request at least `64` if AWS asks for a number and you are using
   `c7g.metal`; request `128` if you want one host plus breathing room.
8. Wait for approval before trying to launch the bare-metal host.

Also check that the instance type exists in your selected region:

```bash
aws ec2 describe-instance-type-offerings \
  --location-type region \
  --filters Name=instance-type,Values="$CHM_INSTANCE_TYPE" \
  --query 'InstanceTypeOfferings[].InstanceType' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION"
```

If that prints nothing, pick another region or another arm64 `*.metal` instance
type.

In the EC2 Console:

1. Open **EC2**.
2. Go to **Instance Types**.
3. Search for `metal` and `arm64` / Graviton families.
4. Confirm the selected region has a suitable type, such as `c7g.metal`.

If there is no bare-metal arm64 instance type in the region, or the quota
increase is not approved, do not continue in that region.

## Step 5: Create a private S3 bucket for snapshot handoff

Bucket names are globally unique, so choose your own:

```bash
export CHM_BUCKET=<your-unique-chm-snapshot-bucket>
```

Create the bucket:

```bash
aws s3 mb "s3://$CHM_BUCKET" \
  --profile chm-aws \
  --region "$AWS_REGION"
```

Block public access:

```bash
aws s3api put-public-access-block \
  --bucket "$CHM_BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile chm-aws \
  --region "$AWS_REGION"
```

Add a lifecycle rule so old experimental artifacts expire automatically after 7
days:

```bash
cat >/tmp/chm-s3-lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "expire-cloud-hypervisor-mac-artifacts",
      "Status": "Enabled",
      "Filter": { "Prefix": "cloud-hypervisor-mac/" },
      "Expiration": { "Days": 7 },
      "AbortIncompleteMultipartUpload": { "DaysAfterInitiation": 1 }
    }
  ]
}
JSON

aws s3api put-bucket-lifecycle-configuration \
  --bucket "$CHM_BUCKET" \
  --lifecycle-configuration file:///tmp/chm-s3-lifecycle.json \
  --profile chm-aws \
  --region "$AWS_REGION"
```

Smoke test:

```bash
echo "hello from chm aws setup" >/tmp/chm-smoke.txt
aws s3 cp /tmp/chm-smoke.txt "s3://$CHM_BUCKET/cloud-hypervisor-mac/smoke.txt" \
  --profile chm-aws \
  --region "$AWS_REGION"
aws s3 rm "s3://$CHM_BUCKET/cloud-hypervisor-mac/smoke.txt" \
  --profile chm-aws \
  --region "$AWS_REGION"
```

## Step 6: Create or choose network access

Beginner path:

1. Use the default VPC in your selected region.
2. Use a public subnet.
3. Avoid NAT Gateway.
4. Either use SSH from your current IP or use SSM Session Manager.

If using SSH, create a security group that only allows your IP:

```bash
export MY_IP=$(curl -s https://checkip.amazonaws.com)/32
export VPC_ID=$(aws ec2 describe-vpcs \
  --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION")

export CHM_SG_ID=$(aws ec2 create-security-group \
  --group-name cloud-hypervisor-mac-capture \
  --description "cloud-hypervisor-mac capture host" \
  --vpc-id "$VPC_ID" \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Project,Value=cloud-hypervisor-mac}]' \
  --query 'GroupId' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION")

aws ec2 authorize-security-group-ingress \
  --group-id "$CHM_SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr "$MY_IP" \
  --profile chm-aws \
  --region "$AWS_REGION"
```

## Step 7: Create an SSH key pair

```bash
aws ec2 create-key-pair \
  --key-name cloud-hypervisor-mac-capture \
  --tag-specifications 'ResourceType=key-pair,Tags=[{Key=Project,Value=cloud-hypervisor-mac}]' \
  --query 'KeyMaterial' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION" > ~/.ssh/cloud-hypervisor-mac-capture.pem

chmod 600 ~/.ssh/cloud-hypervisor-mac-capture.pem
```

If the key already exists, either reuse it or delete/recreate it deliberately.

## Step 8: Pick an Ubuntu arm64 AMI

Use the AWS Console if you are unsure:

1. Open **EC2**.
2. Click **Launch instance**.
3. Search for **Ubuntu Server arm64**.
4. Copy the AMI ID for your region.

Then set:

```bash
export CHM_AMI_ID=<ami-id>
```

## Step 9: Launch the bare-metal capture host

Choose the instance type you have quota for:

```bash
export CHM_INSTANCE_TYPE=c7g.metal
```

Pick a subnet from your default VPC:

```bash
export CHM_SUBNET_ID=$(aws ec2 describe-subnets \
  --filters Name=vpc-id,Values="$VPC_ID" Name=default-for-az,Values=true \
  --query 'Subnets[0].SubnetId' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION")
```

Launch:

```bash
export CHM_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$CHM_AMI_ID" \
  --instance-type "$CHM_INSTANCE_TYPE" \
  --key-name cloud-hypervisor-mac-capture \
  --security-group-ids "$CHM_SG_ID" \
  --subnet-id "$CHM_SUBNET_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=100,VolumeType=gp3,DeleteOnTermination=true}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=cloud-hypervisor-mac},{Key=Name,Value=cloud-hypervisor-mac-capture}]' \
  --query 'Instances[0].InstanceId' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION")

aws ec2 wait instance-running \
  --instance-ids "$CHM_INSTANCE_ID" \
  --profile chm-aws \
  --region "$AWS_REGION"
```

Get its public DNS:

```bash
export CHM_HOST=$(aws ec2 describe-instances \
  --instance-ids "$CHM_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicDnsName' \
  --output text \
  --profile chm-aws \
  --region "$AWS_REGION")

echo "$CHM_HOST"
```

## Step 10: SSH in and check KVM

```bash
ssh -i ~/.ssh/cloud-hypervisor-mac-capture.pem "ubuntu@$CHM_HOST"
```

On the AWS host:

```bash
sudo apt-get update
sudo apt-get install -y build-essential git curl jq qemu-utils pkg-config libssl-dev
test -e /dev/kvm && echo "KVM is present"
```

If `/dev/kvm` is missing, stop and terminate the instance. It is not suitable.

## Step 11: Snapshot compatibility requirement

For macOS Hypervisor.framework today, do **not** capture a stock ITS/LPI-routed
arm64 cloud-hypervisor snapshot. Apple's managed GIC cannot deliver LPIs to a
normal EL1 guest.

The capture must use the project-supported **GICv2M/message-SPI** path so virtio
completion interrupts are deliverable locally through `hv_gic_send_msi` and the
proven 1-of-N SPI route.

## Step 12: First manual proof loop

The first milestone should prove this manually before the app automates it:

1. Local Mac launches or connects to the AWS capture host.
2. Remote host builds/runs the compatible cloud-hypervisor capture workload.
3. Remote host creates a snapshot bundle.
4. Local Mac optionally runs a capture command over SSH, copies the bundle down,
   and uploads a copy to S3 for handoff/audit:

```bash
target/debug/chm cloud capture aws \
  --name <name> \
  --host "ubuntu@$CHM_HOST" \
  --ssh-key ~/.ssh/cloud-hypervisor-mac-capture.pem \
  --remote-capture-command 'CH_GIC_V2M=1 ./capture.sh' \
  --remote-snapshot-dir <snapshot-dir> \
  --to ./snapshots
```

If the remote host has already produced the bundle, omit
`--remote-capture-command`.

6. Local Mac runs:

```bash
target/debug/chm ./snapshots/<name> --max-seconds 30 --idle-exit 0
```

7. Local Mac uploads changed overlay/proof artifacts back to S3:

```bash
target/debug/chm cloud push aws \
  --name <name> \
  --from-local ./snapshots/<name>/.chm-overlays
```

To retrieve a previously uploaded snapshot bundle on another Mac, use:

```bash
target/debug/chm cloud pull aws --name <name> --to ./snapshots
```

8. Local Mac copies return artifacts back to the remote host if needed:

```bash
rsync -avz \
  -e "ssh -i ~/.ssh/cloud-hypervisor-mac-capture.pem" \
  ./snapshots/<name>/.chm-overlays/ \
  "ubuntu@$CHM_HOST:~/chm-return/<name>/.chm-overlays/"
```

This avoids putting AWS credentials on the remote host for the first prototype.
Later, the local app can attach a narrow instance role and let the capture host
upload directly to S3.

## Stop spending money

Use this any time you want to remove project resources.

Dry-run first:

```bash
target/debug/chm cloud cleanup aws \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --project cloud-hypervisor-mac \
  --bucket "$CHM_BUCKET"
```

Actually delete tagged AWS resources and the project S3 prefix:

```bash
target/debug/chm cloud cleanup aws \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --project cloud-hypervisor-mac \
  --bucket "$CHM_BUCKET" \
  --execute \
  --yes
```

Delete the bucket too:

```bash
target/debug/chm cloud cleanup aws \
  --profile chm-aws \
  --region "$AWS_REGION" \
  --project cloud-hypervisor-mac \
  --bucket "$CHM_BUCKET" \
  --delete-bucket \
  --execute \
  --yes
```

The cleanup script targets:

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

## Console checklist

Before you walk away from AWS, check these console pages:

1. **EC2 -> Instances:** no `cloud-hypervisor-mac` instances running or stopped.
2. **EC2 -> Volumes:** no unattached test volumes.
3. **EC2 -> Elastic IPs:** no allocated project IPs.
4. **VPC -> NAT Gateways:** none created for this project.
5. **S3:** only the artifacts you intentionally kept.
6. **Billing -> Cost Explorer:** check the next day for unexpected spend.
