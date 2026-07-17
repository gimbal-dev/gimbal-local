// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Local-managed cloud helper commands for the BYO-subscription loop.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::env;

const DEFAULT_PROJECT: &str = "gimbal-local";
const DEFAULT_INSTANCE_TYPE: &str = "c7g.metal";
const DEFAULT_PREFIX: &str = "gimbal-local/";
const ON_DEMAND_STANDARD_QUOTA: &str = "L-1216C47A";

pub(crate) fn cloud_main(raw: &[String]) -> ExitCode {
    match parse(raw) {
        CloudCommand::InitAws(args) => match init_aws(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::PreflightAws(args) => match preflight_aws(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::PullAws(args) => match pull_aws(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::PushAws(args) => match push_aws(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::CaptureAws(args) => match capture_aws(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("chm cloud: error: {e}");
                ExitCode::FAILURE
            }
        },
        CloudCommand::CleanupAws(args) => cleanup_aws(args),
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
    prefix: String,
    name: Option<String>,
    from_local: Option<PathBuf>,
    to: Option<PathBuf>,
    host: Option<String>,
    ssh_key: Option<PathBuf>,
    remote_capture_command: Option<String>,
    remote_snapshot_dir: Option<String>,
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
            prefix: DEFAULT_PREFIX.to_string(),
            name: None,
            from_local: None,
            to: None,
            host: None,
            ssh_key: None,
            remote_capture_command: None,
            remote_snapshot_dir: None,
            execute: false,
            yes: false,
            delete_bucket: false,
        }
    }
}

enum CloudCommand {
    InitAws(AwsArgs),
    PreflightAws(AwsArgs),
    PullAws(AwsArgs),
    PushAws(AwsArgs),
    CaptureAws(AwsArgs),
    CleanupAws(AwsArgs),
    Help,
    Error(String),
}

fn usage() -> String {
    "chm cloud — local-managed BYO cloud helpers\n\
     \n\
     USAGE:\n    \
         chm cloud init aws --profile P --region R --bucket B [OPTIONS]\n    \
         chm cloud preflight aws --profile P --region R [OPTIONS]\n    \
         chm cloud pull aws --name N [--to DIR] [OPTIONS]\n    \
         chm cloud push aws --name N --from-local DIR [OPTIONS]\n    \
         chm cloud capture aws --name N --host USER@HOST --remote-snapshot-dir D [OPTIONS]\n    \
         chm cloud cleanup aws --profile P --region R [OPTIONS]\n\
     \n\
     COMMON AWS OPTIONS:\n    \
         --profile NAME           AWS CLI profile to use.\n    \
         --region REGION          AWS region to use.\n    \
         --bucket NAME            S3 snapshot bucket.\n    \
         --prefix PREFIX          S3 object prefix (default gimbal-local/).\n    \
         --project VALUE          Project tag value (default gimbal-local).\n    \
         --instance-type TYPE     Capture host type to check (default c7g.metal).\n\
     \n\
     TRANSFER OPTIONS:\n    \
         --name NAME              Snapshot/artifact logical name.\n    \
         --to DIR                 Local destination directory.\n    \
         --from-local DIR         Local source directory for pushed artifacts.\n    \
         --host USER@HOST         Existing SSH capture host.\n    \
         --ssh-key PATH           Optional SSH private key for rsync.\n    \
         --remote-capture-command CMD\n                              Optional SSH command to run before rsync.\n    \
         --remote-snapshot-dir D  Remote snapshot directory to import.\n\
     \n\
     CLEANUP OPTIONS:\n    \
         --delete-bucket          Delete the bucket too.\n    \
         --execute --yes          Actually delete; omitted means dry-run.\n\
     \n\
     NOTES:\n    \
         preflight is read-only. It checks AWS login, the EC2 On-Demand Standard\n    \
         vCPU quota, selected instance type availability, and optional S3 bucket\n    \
         access before any paid capture host is launched. init writes only local\n    \
         config under ~/Library/Application Support/gimbal-local.\n"
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
        "init" => CloudCommand::InitAws(args),
        "preflight" => CloudCommand::PreflightAws(args),
        "pull" => CloudCommand::PullAws(args),
        "push" => CloudCommand::PushAws(args),
        "capture" => CloudCommand::CaptureAws(args),
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
            "--prefix" => {
                i += 1;
                args.prefix = value(raw, i, a)?;
            }
            "--instance-type" => {
                i += 1;
                args.instance_type = value(raw, i, a)?;
            }
            "--name" => {
                i += 1;
                args.name = Some(value(raw, i, a)?);
            }
            "--from-local" => {
                i += 1;
                args.from_local = Some(PathBuf::from(value(raw, i, a)?));
            }
            "--to" => {
                i += 1;
                args.to = Some(PathBuf::from(value(raw, i, a)?));
            }
            "--host" => {
                i += 1;
                args.host = Some(value(raw, i, a)?);
            }
            "--ssh-key" => {
                i += 1;
                args.ssh_key = Some(PathBuf::from(value(raw, i, a)?));
            }
            "--remote-capture-command" => {
                i += 1;
                args.remote_capture_command = Some(value(raw, i, a)?);
            }
            "--remote-snapshot-dir" => {
                i += 1;
                args.remote_snapshot_dir = Some(value(raw, i, a)?);
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

fn init_aws(args: &AwsArgs) -> Result<(), String> {
    require(&args.profile, "--profile")?;
    require(&args.region, "--region")?;
    require(&args.bucket, "--bucket")?;

    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut out = String::new();
    if let Some(profile) = &args.profile {
        out.push_str(&format!("profile={profile}\n"));
    }
    if let Some(region) = &args.region {
        out.push_str(&format!("region={region}\n"));
    }
    if let Some(bucket) = &args.bucket {
        out.push_str(&format!("bucket={bucket}\n"));
    }
    out.push_str(&format!("project={}\n", args.project));
    out.push_str(&format!("instance_type={}\n", args.instance_type));
    out.push_str(&format!("prefix={}\n", normalized_prefix(&args.prefix)));
    fs::write(&path, out).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!("wrote AWS cloud config: {}", path.display());
    println!("run `chm cloud preflight aws` before launching any paid resources");
    Ok(())
}

fn preflight_aws(mut args: AwsArgs) -> Result<(), String> {
    apply_config(&mut args)?;
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

    let ident = aws_capture(&args, &["sts", "get-caller-identity", "--output", "json"])?;
    println!("✓ aws identity available");
    print_indented(&ident);

    let quota = aws_capture(
        &args,
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
        &args,
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
        &args,
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
        aws_capture(&args, &["s3api", "head-bucket", "--bucket", bucket])?;
        println!("✓ S3 bucket exists and is accessible: {bucket}");

        let pab = aws_capture(
            &args,
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

fn pull_aws(mut args: AwsArgs) -> Result<(), String> {
    apply_config(&mut args)?;
    let name = require(&args.name, "--name")?;
    let bucket = require(&args.bucket, "--bucket")?;
    let dest_root = args
        .to
        .clone()
        .unwrap_or_else(|| PathBuf::from("snapshots"));
    let dest = dest_root.join(name);
    fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let src = snapshot_uri(bucket, &args.prefix, name);
    println!("syncing {src} -> {}", dest.display());
    aws_status(&args, &["s3", "sync", &src, path_str(&dest)?])?;
    Ok(())
}

fn push_aws(mut args: AwsArgs) -> Result<(), String> {
    apply_config(&mut args)?;
    let name = require(&args.name, "--name")?;
    let bucket = require(&args.bucket, "--bucket")?;
    let from = args
        .from_local
        .as_deref()
        .ok_or_else(|| "--from-local is required".to_string())?;
    if !from.exists() {
        return Err(format!("{} does not exist", from.display()));
    }
    let dest = return_uri(bucket, &args.prefix, name);
    println!("syncing {} -> {dest}", from.display());
    aws_status(&args, &["s3", "sync", path_str(from)?, &dest])?;
    Ok(())
}

fn capture_aws(mut args: AwsArgs) -> Result<(), String> {
    apply_config(&mut args)?;
    let name = require(&args.name, "--name")?.to_string();
    let host = require(&args.host, "--host")?.to_string();
    let remote = require(&args.remote_snapshot_dir, "--remote-snapshot-dir")?.to_string();
    let bucket = require(&args.bucket, "--bucket")?.to_string();
    let dest_root = args
        .to
        .clone()
        .unwrap_or_else(|| PathBuf::from("snapshots"));
    let dest = dest_root.join(&name);
    fs::create_dir_all(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;

    if let Some(remote_cmd) = &args.remote_capture_command {
        let mut ssh = Command::new("ssh");
        if let Some(key) = &args.ssh_key {
            ssh.arg("-i").arg(key);
        }
        ssh.arg(&host).arg(remote_cmd);
        run_status(&mut ssh)?;
    }

    let mut rsync = Command::new("rsync");
    rsync.arg("-avz");
    if let Some(key) = &args.ssh_key {
        rsync.arg("-e").arg(format!("ssh -i {}", key.display()));
    }
    rsync.arg(format!("{host}:{}/", remote.trim_end_matches('/')));
    rsync.arg(&dest);
    run_status(&mut rsync)?;

    let upload = snapshot_uri(&bucket, &args.prefix, &name);
    println!("syncing imported snapshot {} -> {upload}", dest.display());
    aws_status(&args, &["s3", "sync", path_str(&dest)?, &upload])?;
    Ok(())
}

fn cleanup_aws(mut args: AwsArgs) -> ExitCode {
    if let Err(e) = apply_config(&mut args) {
        eprintln!("chm cloud: {e}");
        return ExitCode::FAILURE;
    }
    let Some(region) = args.region.as_deref() else {
        eprintln!("chm cloud: --region is required");
        return ExitCode::FAILURE;
    };
    let script = cleanup_script();
    let mut cmd = Command::new(&script);
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

    match run_status_code(&mut cmd) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("chm cloud: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cleanup_script() -> PathBuf {
    let repo_script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("scripts")
        .join("aws-cleanup-chm.sh");
    if repo_script.exists() {
        repo_script
    } else {
        PathBuf::from("scripts/aws-cleanup-chm.sh")
    }
}

fn apply_config(args: &mut AwsArgs) -> Result<(), String> {
    let Some(cfg) = load_config()? else {
        return Ok(());
    };
    if args.profile.is_none() {
        args.profile = cfg.profile;
    }
    if args.region.is_none() {
        args.region = cfg.region;
    }
    if args.bucket.is_none() {
        args.bucket = cfg.bucket;
    }
    if args.project == DEFAULT_PROJECT
        && let Some(project) = cfg.project
    {
        args.project = project;
    }
    if args.instance_type == DEFAULT_INSTANCE_TYPE
        && let Some(instance_type) = cfg.instance_type
    {
        args.instance_type = instance_type;
    }
    if args.prefix == DEFAULT_PREFIX
        && let Some(prefix) = cfg.prefix
    {
        args.prefix = prefix;
    }
    args.prefix = normalized_prefix(&args.prefix);
    Ok(())
}

#[derive(Default)]
struct AwsConfig {
    profile: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    project: Option<String>,
    instance_type: Option<String>,
    prefix: Option<String>,
}

fn load_config() -> Result<Option<AwsConfig>, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut cfg = AwsConfig::default();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "{}:{}: expected key=value",
                path.display(),
                idx + 1
            ));
        };
        let v = Some(v.trim().to_string());
        match k.trim() {
            "profile" => cfg.profile = v,
            "region" => cfg.region = v,
            "bucket" => cfg.bucket = v,
            "project" => cfg.project = v,
            "instance_type" => cfg.instance_type = v,
            "prefix" => cfg.prefix = v,
            other => {
                return Err(format!(
                    "{}:{}: unknown key `{other}`",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }
    Ok(Some(cfg))
}

fn config_path() -> Result<PathBuf, String> {
    let home = env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("gimbal-local")
        .join("cloud-aws.env"))
}

fn require<'a>(v: &'a Option<String>, opt: &str) -> Result<&'a str, String> {
    v.as_deref().ok_or_else(|| format!("{opt} is required"))
}

fn normalized_prefix(prefix: &str) -> String {
    let prefix = prefix.trim_start_matches('/');
    if prefix.is_empty() || prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    }
}

fn snapshot_uri(bucket: &str, prefix: &str, name: &str) -> String {
    format!(
        "s3://{}/{}snapshots/{}/",
        bucket,
        normalized_prefix(prefix),
        name
    )
}

fn return_uri(bucket: &str, prefix: &str, name: &str) -> String {
    format!(
        "s3://{}/{}returns/{}/",
        bucket,
        normalized_prefix(prefix),
        name
    )
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))
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

fn aws_status(args: &AwsArgs, aws_args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("aws");
    cmd.args(aws_args);
    if let Some(region) = &args.region {
        cmd.arg("--region").arg(region);
    }
    if let Some(profile) = &args.profile {
        cmd.arg("--profile").arg(profile);
    }
    run_status(&mut cmd)
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

fn run_status(cmd: &mut Command) -> Result<(), String> {
    match run_status_code(cmd)? {
        0 => Ok(()),
        code => Err(format!("{:?} exited with {code}", cmd.get_program())),
    }
}

fn run_status_code(cmd: &mut Command) -> Result<i32, String> {
    let status = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute {:?}: {e}", cmd.get_program()))?;
    Ok(status.code().unwrap_or(1))
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
    fn parses_aws_transfer_commands() {
        let CloudCommand::PullAws(args) = parse(&s(&[
            "pull",
            "aws",
            "--name",
            "snap1",
            "--bucket",
            "bucket",
            "--prefix",
            "gimbal",
            "--to",
            "local-snaps",
        ])) else {
            panic!("expected pull command");
        };
        assert_eq!(args.name.as_deref(), Some("snap1"));
        assert_eq!(args.to.as_deref(), Some(Path::new("local-snaps")));
        assert_eq!(
            snapshot_uri("bucket", &args.prefix, "snap1"),
            "s3://bucket/gimbal/snapshots/snap1/"
        );

        let CloudCommand::PushAws(args) = parse(&s(&[
            "push",
            "aws",
            "--name",
            "snap1",
            "--bucket",
            "bucket",
            "--from-local",
            "returns",
        ])) else {
            panic!("expected push command");
        };
        assert_eq!(args.from_local.as_deref(), Some(Path::new("returns")));
        assert_eq!(
            return_uri("bucket", &args.prefix, "snap1"),
            "s3://bucket/gimbal-local/returns/snap1/"
        );
    }

    #[test]
    fn parses_aws_capture_import_command() {
        let CloudCommand::CaptureAws(args) = parse(&s(&[
            "capture",
            "aws",
            "--name",
            "snap2",
            "--bucket",
            "bucket",
            "--host",
            "ubuntu@host",
            "--ssh-key",
            "key.pem",
            "--remote-capture-command",
            "CH_GIC_V2M=1 ./capture.sh",
            "--remote-snapshot-dir",
            "/var/lib/chm/out",
        ])) else {
            panic!("expected capture command");
        };
        assert_eq!(args.host.as_deref(), Some("ubuntu@host"));
        assert_eq!(args.ssh_key.as_deref(), Some(Path::new("key.pem")));
        assert_eq!(
            args.remote_capture_command.as_deref(),
            Some("CH_GIC_V2M=1 ./capture.sh")
        );
        assert_eq!(
            args.remote_snapshot_dir.as_deref(),
            Some("/var/lib/chm/out")
        );
    }

    #[test]
    fn normalizes_s3_prefixes() {
        assert_eq!(normalized_prefix("/gimbal"), "gimbal/");
        assert_eq!(normalized_prefix("gimbal/"), "gimbal/");
        assert_eq!(normalized_prefix(""), "");
    }

    #[test]
    fn rejects_unknown_provider() {
        let CloudCommand::Error(msg) = parse(&s(&["preflight", "oci"])) else {
            panic!("expected parse error");
        };
        assert!(msg.contains("unsupported cloud provider"));
    }
}
