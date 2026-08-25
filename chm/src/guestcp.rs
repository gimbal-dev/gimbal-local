// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Put a host file into a running guest, and prove it arrived (#316).
//!
//! # Why this has to exist
//!
//! [`crate::exec`] refuses a framed command longer than [`exec::MAX_SCRIPT`],
//! because a Linux tty in canonical mode silently discards everything past
//! `N_TTY_BUF_SIZE` and an over-long command would arrive mangled rather than
//! fail. That refusal is right. Its advice was not: it said *"put it in a script
//! and run that instead"*, and there was no way to get a script in. `chm` had no
//! `cp`, no file push and no share mount, so the console was the only channel
//! and the console is what had just refused.
//!
//! The measured consequence (#316) was that the documented repair for #315 —
//! install the proxy CA a workspace inherited — **could not be carried out with
//! the documented tools**. The reporter hand-rolled a base64 chunking loop, hit
//! the same wall again staging an agent script, and reused it. That loop is this
//! module, with the parts that were left to the operator done properly.
//!
//! # The transfer
//!
//! The payload crosses as base64 in appends short enough that each one frames
//! inside [`exec::MAX_SCRIPT`], then is decoded guest-side into place:
//!
//! 1. `: > <staging>` — truncate, so a retry cannot append to a previous attempt
//!    and decode into plausible rubbish.
//! 2. `printf %s '<chunk>' >> <staging>` — one per chunk.
//! 3. `base64 -d < <staging> > <dest> && rm -f <staging>`.
//! 4. `sha256sum <dest>` — read back, compared **here**.
//!
//! Every step is a framed [`exec`] with its own exit status, so a step that
//! fails is named at the step that failed. The prior art in
//! [`crate::credproxy::cli::guest_install_transfer`] writes blind console lines
//! and can only discover a problem at the end; this path knows immediately.
//!
//! # Two rules this module exists to keep
//!
//! **A transfer that cannot be verified is not reported as success.** The digest
//! comparison happens in this process against bytes we read ourselves. Asking
//! the guest *"does this match?"* would make the thing being checked the thing
//! answering; asking it for the digest and deciding here does not. If the guest
//! has no `sha256sum` the transfer is reported as unverified and the exit status
//! is a failure, because "the file is probably there" is not a result a script
//! can branch on.
//!
//! **The chunk size is derived, never restated.** [`chunk_capacity`] binary
//! searches the largest chunk whose *real* framed line fits, using the real
//! [`exec::script`]. A literal would be a second copy of `MAX_SCRIPT`'s
//! arithmetic, and the two would drift the first time the framing changed —
//! silently, because an over-long chunk is refused by the daemon and reads as a
//! guest fault.

use std::{fmt::Write as _, fs, path::Path, path::PathBuf, process::ExitCode};

use ring::digest::{SHA256, digest};

use crate::{credproxy::base64, exec, imp::help_anywhere, serve};

/// Exit status when the copy itself failed, distinct from any guest command's.
const CP_FAILURE_EXIT: u8 = 125;

/// Seconds allowed for one chunk append.
///
/// A `printf` completes in microseconds; anything approaching this means the
/// console is not at a prompt, which is a transport failure and should be
/// reported as one rather than waited out.
const CHUNK_TIMEOUT: u64 = 60;

/// Seconds allowed for the decode and the digest, which touch the disk.
const FINISH_TIMEOUT: u64 = 300;

pub(crate) const USAGE: &str = "\
usage: chm cp [--socket PATH] [--timeout SECS] <HOST_FILE> <GUEST_PATH>

Copy a file from this host into a running sandbox, over the same console
channel `chm exec` uses, and verify it arrived by comparing a SHA-256 taken
here against one the guest reports.

The guest needs `base64` and `sha256sum` on its PATH; both are in coreutils and
in busybox's default applets.

    chm cp ./ca-install.sh /tmp/ca.sh
    chm exec -- sh /tmp/ca.sh
";

pub fn cp_main(raw: &[String]) -> ExitCode {
    if help_anywhere(raw) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match cp_client(raw) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chm cp: {e}");
            ExitCode::from(CP_FAILURE_EXIT)
        }
    }
}

/// What one `chm cp` invocation was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CpPlan {
    pub(crate) host: PathBuf,
    pub(crate) guest: String,
    pub(crate) timeout: u64,
}

/// Split `chm cp`'s flags from its two operands.
///
/// The guest path is a string and never a [`PathBuf`]: it names a location in
/// someone else's filesystem, and letting this host's path rules normalise it
/// would quietly rewrite what the caller asked for.
pub(crate) fn parse_cp_args(rest: &[String]) -> Result<CpPlan, String> {
    // `-h` / `--help` never reaches here: `cp_main` answers it before parsing,
    // so the usage page is printed to stdout and the process exits 0 (#417).
    // Leaving a second copy of the rule down here is how the two drift.
    let mut timeout = FINISH_TIMEOUT;
    let mut operands: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--timeout" => {
                let v = rest
                    .get(i + 1)
                    .ok_or("--timeout needs a value in seconds")?;
                timeout = v
                    .parse()
                    .map_err(|_| format!("--timeout: `{v}` is not a number"))?;
                if timeout == 0 {
                    return Err("--timeout must be at least 1 second".to_string());
                }
                i += 1;
            }
            a if a.starts_with('-') && a != "-" => {
                return Err(format!("unknown flag `{a}`\n\n{USAGE}"));
            }
            a => operands.push(a.to_string()),
        }
        i += 1;
    }
    match operands.len() {
        2 => Ok(CpPlan {
            host: PathBuf::from(&operands[0]),
            guest: operands[1].clone(),
            timeout,
        }),
        0 | 1 => Err(format!("needs a host file and a guest path\n\n{USAGE}")),
        n => Err(format!("takes exactly two paths, got {n}\n\n{USAGE}")),
    }
}

fn cp_client(raw: &[String]) -> Result<(), String> {
    let (socket, rest) = serve::take_socket(raw)?;
    let plan = parse_cp_args(&rest)?;

    let bytes = fs::read(&plan.host).map_err(|e| format!("read {}: {e}", plan.host.display()))?;
    let want = transfer(&socket, &bytes, &plan.guest, plan.timeout)?;

    eprintln!(
        "chm cp: {} -> {} ({} bytes, sha256 {want})",
        plan.host.display(),
        plan.guest,
        bytes.len()
    );
    Ok(())
}

/// Carry `bytes` into the guest at `guest`, and return the digest both sides
/// agree on.
///
/// Factored out of [`cp_client`] rather than copied, because the proxy CA
/// installer (#376) has exactly this problem and had been solving it a weaker
/// way: typing the payload at the console and letting the *guest* compare the
/// digest at the end. One implementation is what stops that drifting back to a
/// check the thing under test answers for itself.
///
/// Every failure names the step it happened at, so a partial transfer is
/// reported as a partial transfer rather than as a corrupt file.
pub(crate) fn transfer(
    socket: &Path,
    bytes: &[u8],
    guest: &str,
    timeout: u64,
) -> Result<String, String> {
    let want = sha256_hex(bytes);
    let staging = staging_path();
    let steps = transfer_steps(bytes, &staging, guest)?;

    let n = steps.len();
    for (i, step) in steps.into_iter().enumerate() {
        let step_timeout = if i + 1 == n { timeout } else { CHUNK_TIMEOUT };
        run(socket, step_timeout, &step, i + 1, n)?;
    }

    // Read the digest back and decide here. Asking the guest whether its own
    // copy matches would let the thing under test answer the question.
    let out = run(
        socket,
        timeout,
        &sh(&format!("sha256sum {}", exec::shell_quote(guest))),
        n,
        n,
    )
    .map_err(|e| {
        format!(
            "{} bytes reached {guest} but nothing has checked them: {e}\n\
             the guest needs `sha256sum` for this copy to be verifiable",
            bytes.len(),
        )
    })?;

    verify_digest(&out, &want, guest)?;
    Ok(want)
}

/// Run one framed step, turning a non-zero guest status into a named failure.
fn run(
    socket: &Path,
    timeout: u64,
    argv: &[String],
    step: usize,
    total: usize,
) -> Result<String, String> {
    let reply = serve::exec_once(socket, timeout, argv)?;
    let status = reply
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("error");
    if status != "completed" {
        let detail = reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("no detail");
        return Err(format!("step {step}/{total}: {status}: {detail}"));
    }
    let output = reply
        .get("output")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    match reply.get("exit_code").and_then(|v| v.as_i64()) {
        Some(0) => Ok(output),
        Some(c) => Err(format!(
            "step {step}/{total}: the guest exited {c}: {}",
            output.trim()
        )),
        None => Err(format!(
            "step {step}/{total}: no exit status from the daemon"
        )),
    }
}

/// Wrap a shell fragment as an argv, so the decision to use a shell is visible.
fn sh(fragment: &str) -> Vec<String> {
    // `sh`, not `bash`: an Alpine-derived guest has no bash, and every fragment
    // built here is POSIX.
    vec!["sh".to_string(), "-c".to_string(), fragment.to_string()]
}

/// Where the base64 lands while it is being written.
///
/// Nonce-derived so two concurrent copies cannot append into each other's
/// staging file and each decode the interleaving as its own payload.
fn staging_path() -> String {
    format!("/tmp/.chm-cp-{}", exec::Nonce::mint().token())
}

/// Decide whether the guest's copy is the file we sent.
///
/// Pure, and separated from [`transfer`] deliberately. The comparison is the
/// only thing standing between "the bytes moved" and "the right bytes moved",
/// and `transfer` needs a live daemon so no unit test can reach it — an
/// unreachable decision is one that cannot be proved to fire. Taking the guest's
/// raw `sha256sum` line rather than a pre-extracted field keeps the parsing here
/// too, since a line we failed to understand must not read as a match.
pub(crate) fn verify_digest(reported: &str, want: &str, guest: &str) -> Result<(), String> {
    let got = reported.split_whitespace().next().unwrap_or("");
    if got == want {
        return Ok(());
    }
    Err(format!(
        "{guest} arrived corrupt: the guest reports sha256 {} and this host read {want}\n\
         the guest copy has been left in place for inspection",
        if got.is_empty() {
            "nothing usable"
        } else {
            got
        },
    ))
}

/// Every framed step of one transfer, in order, except the final digest read.
///
/// Separated from the socket so the whole plan is testable: the properties that
/// matter — a truncating first step, chunks that frame, a decode that removes
/// its own staging file — are all decided here.
pub(crate) fn transfer_steps(
    bytes: &[u8],
    staging: &str,
    guest: &str,
) -> Result<Vec<Vec<String>>, String> {
    let q_staging = exec::shell_quote(staging);
    let q_guest = exec::shell_quote(guest);
    let capacity = chunk_capacity(staging)?;

    // Truncate first. Without this a retry after a partial copy appends to what
    // the previous attempt left, and `base64 -d` on the concatenation yields a
    // file that is wrong rather than a step that failed.
    let mut steps = vec![sh(&format!(": > {q_staging}"))];

    let b64 = base64::encode(bytes);
    for chunk in b64.as_bytes().chunks(capacity) {
        // Sound by construction: base64's alphabet is A-Za-z0-9+/= and holds no
        // single quote, so `shell_quote` cannot lengthen it. Asserted by
        // `every_base64_character_survives_quoting_unchanged` rather than left
        // to the reader, because `chunk_capacity` depends on it.
        let part = String::from_utf8_lossy(chunk);
        steps.push(sh(&format!(
            "printf %s {} >> {q_staging}",
            exec::shell_quote(&part)
        )));
    }

    steps.push(sh(&format!(
        "base64 -d < {q_staging} > {q_guest} && rm -f {q_staging}"
    )));

    // The capacity search used one nonce and each step will be framed with
    // another. Nonces are fixed width, so this can only fire if that stops being
    // true — and then it fires here, rather than as a daemon-side refusal that
    // reads like a guest fault.
    for (i, step) in steps.iter().enumerate() {
        if let Err(e) = exec::script(&exec::Nonce::mint(), step) {
            return Err(format!("internal: step {} does not fit: {e}", i + 1));
        }
    }
    Ok(steps)
}

/// The largest chunk whose framed append fits [`exec::MAX_SCRIPT`].
///
/// Searched against the real [`exec::script`] rather than computed from the
/// framing's shape, so that changing the framing changes this automatically. A
/// hand-derived constant here would be a second copy of arithmetic that lives in
/// [`crate::exec`], and the copies would part company silently.
pub(crate) fn chunk_capacity(staging: &str) -> Result<usize, String> {
    let nonce = exec::Nonce::mint();
    let q_staging = exec::shell_quote(staging);
    let fits = |n: usize| {
        let filler = "A".repeat(n);
        let step = sh(&format!(
            "printf %s {} >> {q_staging}",
            exec::shell_quote(&filler)
        ));
        exec::script(&nonce, &step).is_ok()
    };
    if !fits(1) {
        return Err(format!(
            "the guest path {staging} is too long to write to one chunk at a time"
        ));
    }
    let mut lo = 1;
    let mut hi = exec::MAX_SCRIPT;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    Ok(lo)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in digest(&SHA256, bytes).as_ref() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// The whole chunking scheme rests on base64 needing no escaping, because
    /// `chunk_capacity` measures a run of `A` and the real chunks are arbitrary
    /// alphabet characters. If any of them lengthened under quoting, a chunk
    /// could exceed the measured capacity.
    #[test]
    fn every_base64_character_survives_quoting_unchanged() {
        let alphabet: String = ('A'..='Z')
            .chain('a'..='z')
            .chain('0'..='9')
            .chain(['+', '/', '='])
            .collect();
        for c in alphabet.chars() {
            let q = exec::shell_quote(&c.to_string());
            assert_eq!(q.len(), 3, "{c} does not quote to exactly '<c>': {q}");
        }
    }

    #[test]
    fn the_measured_chunk_capacity_is_the_largest_one_that_fits() {
        let staging = "/tmp/.chm-cp-abc123";
        let cap = chunk_capacity(staging).expect("a capacity");
        let nonce = exec::Nonce::mint();
        let frame = |n: usize| {
            let step = sh(&format!(
                "printf %s {} >> {}",
                exec::shell_quote(&"A".repeat(n)),
                exec::shell_quote(staging)
            ));
            exec::script(&nonce, &step)
        };
        assert!(frame(cap).is_ok(), "the reported capacity must fit");
        assert!(frame(cap + 1).is_err(), "one more must not");
    }

    /// A capacity derived from the framing rather than restated must move when
    /// the framing does. Nothing here asserts a number.
    #[test]
    fn the_capacity_leaves_room_for_the_framing() {
        let cap = chunk_capacity("/tmp/.chm-cp-abc123").expect("a capacity");
        assert!(cap > 0);
        assert!(
            cap < exec::MAX_SCRIPT,
            "a chunk cannot be as long as the whole line it is framed into"
        );
    }

    #[test]
    fn the_first_step_truncates_so_a_retry_cannot_append_to_a_partial_copy() {
        let steps = transfer_steps(b"hello", "/tmp/stage", "/tmp/dest").expect("steps");
        assert_eq!(steps[0], s(&["sh", "-c", ": > '/tmp/stage'"]));
    }

    #[test]
    fn the_payload_crosses_as_base64_and_is_decoded_into_place() {
        let steps = transfer_steps(b"hello world", "/tmp/stage", "/tmp/dest").expect("steps");
        let joined: String = steps
            .iter()
            .map(|st| st[2].clone())
            .collect::<Vec<_>>()
            .join("\n");
        let want = base64::encode(b"hello world");
        assert!(joined.contains(&want), "the base64 must appear: {joined}");
        let last = steps.last().expect("a last step");
        assert_eq!(
            last[2],
            "base64 -d < '/tmp/stage' > '/tmp/dest' && rm -f '/tmp/stage'"
        );
    }

    /// A payload far larger than one framed line is what the whole module is
    /// for: #316's CA installer is ~4.1 KB and the limit is 4000 bytes of
    /// *framed* input.
    #[test]
    fn a_payload_larger_than_one_framed_line_is_split_into_steps_that_all_fit() {
        let big = vec![b'x'; 40_000];
        let steps = transfer_steps(&big, "/tmp/stage", "/tmp/dest").expect("steps");
        assert!(
            steps.len() > 10,
            "40 KB must need many chunks, got {}",
            steps.len()
        );
        let nonce = exec::Nonce::mint();
        for (i, step) in steps.iter().enumerate() {
            assert!(exec::script(&nonce, step).is_ok(), "step {i} does not fit");
        }
    }

    /// Reassembling every chunk's payload must give back exactly the base64 of
    /// the input: a chunking bug that dropped or duplicated a boundary would
    /// otherwise decode into a plausible-looking wrong file.
    #[test]
    fn the_chunks_reassemble_to_exactly_the_input() {
        let payload: Vec<u8> = (0..9_000u32).map(|i| (i % 251) as u8).collect();
        let steps = transfer_steps(&payload, "/tmp/stage", "/tmp/dest").expect("steps");
        let mut b64 = String::new();
        for step in &steps {
            let f = &step[2];
            if let Some(rest) = f.strip_prefix("printf %s '") {
                let end = rest.find("' >> ").expect("a terminator");
                b64.push_str(&rest[..end]);
            }
        }
        assert_eq!(base64::decode(&b64).expect("valid base64"), payload);
    }

    #[test]
    fn an_empty_file_still_produces_a_truncate_and_a_decode() {
        let steps = transfer_steps(b"", "/tmp/stage", "/tmp/dest").expect("steps");
        assert_eq!(steps.len(), 2, "truncate then decode, no chunks: {steps:?}");
    }

    /// I5: a guest path is caller-supplied text and must never become shell
    /// syntax. Asked of a real shell rather than by looking for metacharacters,
    /// which is the assertion this repo has got wrong twice (V8.3, V9.7).
    #[test]
    fn a_hostile_guest_path_cannot_break_out_of_its_quotes() {
        let hostile = "/tmp/x'; touch /tmp/chm-cp-pwned; echo '";
        let steps = transfer_steps(b"hi", "/tmp/stage", hostile).expect("steps");
        let decode = &steps.last().expect("a last step")[2];
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "set -- {}; printf %s \"$1\"",
                exec::shell_quote(hostile)
            ))
            .output()
            .expect("run sh");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            hostile,
            "the shell must read the path back unchanged"
        );
        assert!(
            !decode.contains("touch /tmp/chm-cp-pwned; echo ' '"),
            "{decode}"
        );
        assert!(!Path::new("/tmp/chm-cp-pwned").exists());
    }

    #[test]
    fn two_copies_stage_through_different_files() {
        assert_ne!(staging_path(), staging_path());
        assert!(staging_path().starts_with("/tmp/.chm-cp-"));
    }

    #[test]
    fn the_digest_is_this_hosts_own_reading_of_the_bytes() {
        // The value `sha256sum` prints for an empty file, so the comparison this
        // module makes is against the same function the guest computes.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn two_paths_are_required() {
        assert!(parse_cp_args(&s(&["only-one"])).is_err());
        assert!(parse_cp_args(&s(&["a", "b", "c"])).is_err());
        assert!(parse_cp_args(&s(&[])).is_err());
    }

    #[test]
    fn the_operands_keep_their_order_and_the_guest_path_stays_a_string() {
        let plan = parse_cp_args(&s(&["./here.sh", "/tmp/there.sh"])).expect("a plan");
        assert_eq!(plan.host, PathBuf::from("./here.sh"));
        assert_eq!(plan.guest, "/tmp/there.sh");
    }

    /// A guest path is not normalised on the way through: `..` means whatever it
    /// means in the guest, and rewriting it here would silently retarget the
    /// copy.
    #[test]
    fn a_guest_path_is_passed_through_unchanged() {
        let plan = parse_cp_args(&s(&["a", "/tmp/./x/../y.sh"])).expect("a plan");
        assert_eq!(plan.guest, "/tmp/./x/../y.sh");
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_taken_as_a_path() {
        let e = parse_cp_args(&s(&["--into", "a", "b"])).expect_err("refused");
        assert!(e.contains("--into"), "{e}");
    }

    #[test]
    fn a_timeout_needs_a_usable_value() {
        assert!(parse_cp_args(&s(&["--timeout", "0", "a", "b"])).is_err());
        assert!(parse_cp_args(&s(&["--timeout", "x", "a", "b"])).is_err());
        assert!(parse_cp_args(&s(&["--timeout"])).is_err());
        let plan = parse_cp_args(&s(&["--timeout", "42", "a", "b"])).expect("a plan");
        assert_eq!(plan.timeout, 42);
    }

    /// A digest that does not match is a failed copy, not a successful one.
    #[test]
    fn only_the_digest_this_host_computed_counts_as_a_match() {
        let want = sha256_hex(b"the real bytes");
        let line = format!("{want}  /tmp/x");
        verify_digest(&line, &want, "/tmp/x").unwrap();

        let other = sha256_hex(b"something else");
        let e = verify_digest(&format!("{other}  /tmp/x"), &want, "/tmp/x")
            .expect_err("a different digest must not pass");
        assert!(e.contains("arrived corrupt"), "{e}");
        assert!(e.contains(&want) && e.contains(&other), "{e}");
    }

    /// A reply we could not read is a failure, never a pass.
    ///
    /// `sha256sum` missing from the guest, a busybox applet writing to stderr,
    /// or a truncated line all arrive here as something that is not a digest.
    /// The dangerous direction is treating that as agreement, so an empty reply
    /// is checked explicitly rather than left to string equality.
    #[test]
    fn an_unreadable_reply_is_not_a_match() {
        let want = sha256_hex(b"payload");
        for reply in ["", "   \n", "sha256sum: not found"] {
            let Err(e) = verify_digest(reply, &want, "/tmp/x") else {
                panic!("an unreadable reply must not pass: {reply:?}");
            };
            assert!(e.contains("arrived corrupt"), "{e}");
        }
        assert!(
            verify_digest("", &want, "/tmp/x")
                .unwrap_err()
                .contains("nothing usable"),
            "an empty reply should say so rather than print a blank digest"
        );
    }

    /// #316: the verification has to still be on the path that reports success.
    ///
    /// Deleting the call leaves this file compiling and every other test green,
    /// because an assertion about an outcome structurally cannot see a path that
    /// is no longer taken — this repo has now paid for that eight times. The
    /// needle is assembled so it is not satisfied by its own appearance here.
    ///
    /// #376 added a second reporter: `chm proxy ca --install` carries its
    /// payload through the same [`transfer`]. So the guard now has to hold two
    /// things — that `transfer` compares, and that `cp_client` still goes
    /// through `transfer` rather than growing its own copy of the sequence,
    /// which is how the CA install came to have a weaker check in the first
    /// place.
    #[test]
    fn the_transfer_cannot_report_success_without_comparing_the_digest() {
        let src = include_str!("guestcp.rs");
        let call = format!("{}(&out, &want, guest)?", "verify_digest");
        assert!(
            src.contains(&call),
            "transfer no longer compares the digest, so every caller reports \
             success for any bytes that arrive"
        );
        let via = format!(
            "{}(&socket, &bytes, &plan.guest, plan.timeout)?",
            "transfer"
        );
        assert!(
            src.contains(&via),
            "cp_client no longer goes through transfer, so `chm cp` and the CA \
             install can drift apart again"
        );
    }
}
