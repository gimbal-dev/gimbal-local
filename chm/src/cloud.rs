// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Local-managed cloud helper commands for the BYO-subscription loop.

use std::process::{Command, ExitCode};

const DEFAULT_PROJECT: &str = "cloud-hypervisor-mac";
const DEFAULT_INSTANCE_TYPE: &str = "c7g.metal";
const ON_DEMAND_STANDARD_QUOTA: &str = "L-1216C47A";

pub(crate) fn cloud_main(raw: &[String]) -> ExitCode {
    match parse(raw) {
        CloudCommand::PreflightAws(args) => match preflight_aws(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::CleanupAws(args) => cleanup_aws(&args),
        CloudCommand::Help => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        CloudCommand::Error(msg) => {
            eprintln!("chm cloud: {msg}\n");
            eprint!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
struct AwsArgs {
    profile: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    project: String,
    instance_type: String,
    execute: bool,
    yes: bool,
    delete_bucket: bool,
}

impl Default for AwsArgs {
    fn default() -> Self {
        Self {
            profile: None,
            region: None,
            bucket: None,
            project: DEFAULT_PROJECT.to_string(),
            instance_type: DEFAULT_INSTANCE_TYPE.to_string(),
            execute: false,
            yes: false,
            delete_bucket: false,
        }
    }
}

enum CloudCommand {
    PreflightAws(AwsArgs),
    CleanupAws(AwsArgs),
    Help,
    Error(String),
}

fn usage() -> String {
    "chm cloud — local-managed BYO cloud helpers\n\
     \n\
     USAGE:\n    \
         chm cloud preflight aws --profile P --region R [OPTIONS]\n    \
         chm cloud cleanup aws --profile P --region R [OPTIONS]\n\
     \n\
     PREFLIGHT OPTIONS:\n    \
         --profile NAME           AWS CLI profile to use.\n    \
         --region REGION          AWS region to inspect.\n    \
         --bucket NAME            Optional S3 snapshot bucket to check.\n    \
         --instance-type TYPE     Capture host type to check (default c7g.metal).\n\
     \n\
     CLEANUP OPTIONS:\n    \
         --profile NAME           AWS CLI profile to use.\n    \
         --region REGION          AWS region to clean.\n    \
         --project VALUE          Project tag value (default cloud-hypervisor-mac).\n    \
         --bucket NAME            Optional S3 bucket to clean.\n    \
         --delete-bucket          Delete the bucket too.\n    \
         --execute --yes          Actually delete; omitted means dry-run.\n\
     \n\
     NOTES:\n    \
         preflight is read-only. It checks AWS login, the EC2 On-Demand Standard\n    \
         vCPU quota, selected instance type availability, and optional S3 bucket\n    \
         access before any paid capture host is launched.\n"
        .to_string()
}

fn parse(raw: &[String]) -> CloudCommand {
    if raw.is_empty() {
        return CloudCommand::Help;
    }
    if matches!(raw[0].as_str(), "-h" | "--help") {
        return CloudCommand::Help;
    }
    if raw.len() < 2 {
        return CloudCommand::Error("expected `<command> aws`".into());
    }
    let provider = raw[1].as_str();
    if provider != "aws" {
        return CloudCommand::Error(format!("unsupported cloud provider `{provider}`"));
    }
    let args = match parse_aws_args(&raw[2..]) {
        Ok(args) => args,
        Err(ParseAwsError::Help) => return CloudCommand::Help,
        Err(ParseAwsError::Error(e)) => return CloudCommand::Error(e),
    };
    match raw[0].as_str() {
        "preflight" => CloudCommand::PreflightAws(args),
        "cleanup" => CloudCommand::CleanupAws(args),
        other => CloudCommand::Error(format!("unknown cloud command `{other}`")),
    }
}

enum ParseAwsError {
    Help,
    Error(String),
}

fn parse_aws_args(raw: &[String]) -> Result<AwsArgs, ParseAwsError> {
    let mut args = AwsArgs::default();
    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "--profile" => {
                i += 1;
                args.profile = Some(value(raw, i, a)?);
            }
            "--region" => {
                i += 1;
                args.region = Some(value(raw, i, a)?);
            }
            "--bucket" => {
                i += 1;
                args.bucket = Some(value(raw, i, a)?);
            }
            "--project" => {
                i += 1;
                args.project = value(raw, i, a)?;
            }
            "--instance-type" => {
                i += 1;
                args.instance_type = value(raw, i, a)?;
            }
            "--execute" => args.execute = true,
            "--yes" => args.yes = true,
            "--delete-bucket" => args.delete_bucket = true,
            "-h" | "--help" => return Err(ParseAwsError::Help),
            other => return Err(ParseAwsError::Error(format!("unknown option `{other}`"))),
        }
        i += 1;
    }
    Ok(args)
}

fn value(raw: &[String], i: usize, opt: &str) -> Result<String, ParseAwsError> {
    raw.get(i)
        .cloned()
        .ok_or_else(|| ParseAwsError::Error(format!("{opt} requires a value")))
}

fn preflight_aws(args: &AwsArgs) -> Result<(), String> {
    let region = args
        .region
        .as_deref()
        .ok_or_else(|| "--region is required".to_string())?;

    println!("chm cloud preflight aws");
    println!("  region:        {region}");
    println!(
        "  profile:       {}",
        args.profile.as_deref().unwrap_or("(default)")
    );
    println!("  instance type: {}", args.instance_type);
    if let Some(bucket) = &args.bucket {
        println!("  bucket:        {bucket}");
    }
    println!();

    let version = run_capture(Command::new("aws").arg("--version"))?;
    println!("✓ aws cli: {}", version.trim());

    let ident = aws_capture(args, &["sts", "get-caller-identity", "--output", "json"])?;
    println!("✓ aws identity available");
    print_indented(&ident);

    let quota = aws_capture(
        args,
        &[
            "service-quotas",
            "get-service-quota",
            "--service-code",
            "ec2",
            "--quota-code",
            ON_DEMAND_STANDARD_QUOTA,
            "--query",
            "Quota.Value",
            "--output",
            "text",
        ],
    )?;
    let quota = parse_f64("quota", &quota)?;

    let vcpus = aws_capture(
        args,
        &[
            "ec2",
            "describe-instance-types",
            "--instance-types",
            &args.instance_type,
            "--query",
            "InstanceTypes[0].VCpuInfo.DefaultVCpus",
            "--output",
            "text",
        ],
    )?;
    let vcpus = parse_f64("instance vCPU count", &vcpus)?;

    println!(
        "✓ quota {ON_DEMAND_STANDARD_QUOTA}: {quota:.0} vCPUs; {} needs {vcpus:.0} vCPUs",
        args.instance_type
    );
    if quota < vcpus {
        return Err(format!(
            "quota is too low: {quota:.0} vCPUs available, {} needs {vcpus:.0}. \
             Request at least {vcpus:.0} vCPUs, or 128 for breathing room.",
            args.instance_type
        ));
    }

    let offering = aws_capture(
        args,
        &[
            "ec2",
            "describe-instance-type-offerings",
            "--location-type",
            "region",
            "--filters",
            &format!("Name=instance-type,Values={}", args.instance_type),
            "--query",
            "InstanceTypeOfferings[].InstanceType",
            "--output",
            "text",
        ],
    )?;
    if offering.trim().is_empty() || offering.trim() == "None" {
        return Err(format!("{} is not offered in {region}", args.instance_type));
    }
    println!("✓ {} is offered in {region}", args.instance_type);

    if let Some(bucket) = &args.bucket {
        aws_capture(args, &["s3api", "head-bucket", "--bucket", bucket])?;
        println!("✓ S3 bucket exists and is accessible: {bucket}");

        let pab = aws_capture(
            args,
            &[
                "s3api",
                "get-public-access-block",
                "--bucket",
                bucket,
                "--query",
                "PublicAccessBlockConfiguration",
                "--output",
                "json",
            ],
        )?;
        println!("✓ S3 public-access-block is configured");
        print_indented(&pab);
    }

    println!();
    println!("Preflight passed. This does not launch or create paid resources.");
    Ok(())
}

fn cleanup_aws(args: &AwsArgs) -> ExitCode {
    let Some(region) = args.region.as_deref() else {
        eprintln!("chm cloud: --region is required");
        return ExitCode::FAILURE;
    };
    let script = "scripts/aws-cleanup-chm.sh";
    let mut cmd = Command::new(script);
    cmd.arg("--region").arg(region);
    cmd.arg("--project").arg(&args.project);
    if let Some(profile) = &args.profile {
        cmd.arg("--profile").arg(profile);
    }
    if let Some(bucket) = &args.bucket {
        cmd.arg("--bucket").arg(bucket);
    }
    if args.delete_bucket {
        cmd.arg("--delete-bucket");
    }
    if args.execute {
        cmd.arg("--execute");
    }
    if args.yes {
        cmd.arg("--yes");
    }

    match cmd.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("chm cloud: failed to run {script}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn aws_capture(args: &AwsArgs, aws_args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("aws");
    cmd.args(aws_args);
    if let Some(region) = &args.region {
        cmd.arg("--region").arg(region);
    }
    if let Some(profile) = &args.profile {
        cmd.arg("--profile").arg(profile);
    }
    run_capture(&mut cmd)
}

fn run_capture(cmd: &mut Command) -> Result<String, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("failed to execute {:?}: {e}", cmd.get_program()))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        let err = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(err.to_string());
    }
    if stdout.trim().is_empty() {
        Ok(stderr)
    } else {
        Ok(stdout)
    }
}

fn parse_f64(name: &str, s: &str) -> Result<f64, String> {
    s.trim()
        .parse()
        .map_err(|_| format!("could not parse {name}: `{}`", s.trim()))
}

fn print_indented(s: &str) {
    for line in s.trim().lines() {
        println!("    {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn parses_aws_preflight_defaults() {
        let CloudCommand::PreflightAws(args) = parse(&s(&[
            "preflight",
            "aws",
            "--profile",
            "chm-aws",
            "--region",
            "us-east-1",
        ])) else {
            panic!("expected preflight command");
        };
        assert_eq!(args.profile.as_deref(), Some("chm-aws"));
        assert_eq!(args.region.as_deref(), Some("us-east-1"));
        assert_eq!(args.instance_type, DEFAULT_INSTANCE_TYPE);
    }

    #[test]
    fn parses_aws_cleanup_execute_guard_flags() {
        let CloudCommand::CleanupAws(args) = parse(&s(&[
            "cleanup",
            "aws",
            "--profile",
            "chm-aws",
            "--region",
            "us-east-1",
            "--bucket",
            "snapshots",
            "--delete-bucket",
            "--execute",
            "--yes",
        ])) else {
            panic!("expected cleanup command");
        };
        assert_eq!(args.bucket.as_deref(), Some("snapshots"));
        assert!(args.delete_bucket);
        assert!(args.execute);
        assert!(args.yes);
    }

    #[test]
    fn rejects_unknown_provider() {
        let CloudCommand::Error(msg) = parse(&s(&["preflight", "oci"])) else {
            panic!("expected parse error");
        };
        assert!(msg.contains("unsupported cloud provider"));
    }
}
