// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Carry `env` and `postBootCommand` from a spec into a guest that is running.
//!
//! V9.3 gave both fields a home in `sandbox.json` and then **refused** them,
//! because nothing on the `chm create` side could deliver either across the
//! boundary. This is the delivery (#190 / G22).
//!
//! # Readiness is proven, never pattern-matched
//!
//! The hard part is not writing to the console — [`crate::exec`] already does
//! that — it is knowing *when*. A guest is not ready when the kernel has booted;
//! it is ready when something on the serial line will read a command and run it.
//!
//! The obvious approach is to watch for a prompt. It is also wrong here: this
//! build's whole premise is bring-your-own images, so there is no prompt to
//! match. `#` and `$` appear in kernel output; a distro may print a login
//! banner, an OpenRC summary, or nothing at all; and a regex tuned on the images
//! we happen to own would fail silently on the first image we do not.
//!
//! So readiness is established the only way that generalises: **send a framed
//! no-op and see whether the answer comes back**. If the end marker appears, a
//! shell read our line and ran it — that is not evidence of readiness, it *is*
//! readiness, and it is true of any image with a shell on the console. If it
//! does not, retry until the deadline. The probe is idempotent by construction
//! (`true`), so a retry that races a slow guest costs nothing.
//!
//! A shell that is not yet listening simply loses the bytes it was sent, which
//! is why the probe repeats rather than waiting once and giving up.
//!
//! # Why `env` cannot be an argv
//!
//! `export` is a shell builtin, and a builtin run in a subshell changes only the
//! subshell. Sending `["sh", "-c", "export FOO=bar"]` would exit 0, look like it
//! worked, and set nothing the operator would ever see — exactly the class of
//! failure #192 was about. The assignment therefore has to be evaluated by *the
//! console's own shell*, so it is built as a shell fragment and framed with
//! [`exec::frame`].
//!
//! Every **value** is still shell-quoted, and every **name** is validated to be
//! a POSIX identifier first, so nothing an operator supplies can become syntax.
//! A name that is not an identifier cannot be exported by any shell, so refusing
//! it up front turns a silent no-op into a message.
//!
//! # What scope `env` actually reaches
//!
//! The console is one tty with one shell session, and `chm connect` and
//! `chm exec` both attach to that same session. An `export` therefore reaches
//! the post-boot command, every later exec, any process they start, and the
//! operator's own interactive session — which is the useful set.
//!
//! It does **not** survive that shell exiting and a getty respawning a fresh
//! login. That is a real limit and it is stated rather than papered over:
//! persisting it would mean writing into the guest's filesystem, which needs a
//! writable rootfs this build cannot assume of a BYO image. [`Report`] carries
//! the scope so a caller can say so instead of implying more than was done.

use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

use crate::exec;
use crate::exec::{ExecOutcome, Nonce};

/// How long to keep probing for a shell before giving up.
///
/// Generous because the cost of being wrong is asymmetric: a slow guest that is
/// declared dead loses its `postBootCommand` for no reason, while waiting a
/// little longer on a genuinely dead one only delays an error that is about to
/// be reported anyway.
pub(crate) const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a single delivered step may take once the guest is answering.
pub(crate) const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// Gap between readiness probes. Short enough that a guest reaching its prompt
/// is not left idling, long enough not to flood the console of one that is
/// still booting.
const PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// What an operator asked to happen inside the guest once it is up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Environment variables to export, in a stable order.
    pub env: BTreeMap<String, String>,
    /// A command to run after boot. `None` means none was asked for; an empty
    /// argv is rejected at parse time rather than framed and timed out.
    pub post_boot: Option<Vec<String>>,
}

impl Plan {
    /// Nothing to deliver, so nothing to wait for.
    ///
    /// Load-bearing: a run with no spec must not pay a readiness probe, and more
    /// importantly must not be able to fail one. Behaviour on the existing path
    /// is unchanged because the whole mechanism is skipped.
    pub(crate) fn is_empty(&self) -> bool {
        self.env.is_empty() && self.post_boot.is_none()
    }
}

/// How far delivery got, and what the guest said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// Everything asked for ran, and `post_boot_code` is the command's own exit
    /// status when one was asked for.
    Delivered {
        exported: usize,
        post_boot_code: Option<i32>,
    },
    /// Nothing was asked for.
    NothingToDo,
}

/// Why delivery could not be completed.
///
/// Deliberately distinct from "the command failed": a caller must not be able to
/// read *we never got a verdict* as *it worked*, which is the same discipline
/// [`ExecOutcome`] enforces one level down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No shell answered the probe before the deadline.
    ///
    /// `echoed` records whether the console ever produced *any* output while we
    /// were probing. It is the difference between two failures that look
    /// identical from outside and need opposite fixes: nothing is reading the
    /// console at all (no getty, or still booting), versus something is reading
    /// it and cannot answer.
    NeverReady {
        waited: Duration,
        probes: usize,
        echoed: bool,
    },
    /// A step was sent and the guest never finished it.
    NoVerdict { step: String, detail: String },
    /// The step ran and reported failure.
    Failed {
        step: String,
        code: i32,
        output: String,
    },
    /// The plan could not be turned into something sendable.
    Unsendable(String),
    /// The guest stopped while we were waiting on it.
    GuestStopped { step: String },
}

impl Failure {
    /// One line, written for whoever has to fix it.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::NeverReady {
                waited,
                probes,
                echoed,
            } => {
                let base = format!(
                    "no shell answered on the console within {}s ({probes} probes sent), so \
                     `env` and `postBootCommand` could not be delivered.",
                    waited.as_secs()
                );
                if *echoed {
                    format!(
                        "{base} The console did produce output, so something is reading it -- \
                         it accepted every probe and answered none. A shell left mid-command \
                         (an unterminated quote, or a pager or editor holding the terminal) \
                         does exactly this."
                    )
                } else {
                    format!(
                        "{base} The console produced no output at all, so most likely nothing \
                         is listening on it: the guest may have no getty on its serial console, \
                         or may still be booting."
                    )
                }
            }
            Self::NoVerdict { step, detail } => {
                format!("{step}: no result came back from the guest ({detail})")
            }
            Self::Failed { step, code, output } => {
                let tail = output.trim();
                if tail.is_empty() {
                    format!("{step}: exited {code}")
                } else {
                    format!("{step}: exited {code}\n{tail}")
                }
            }
            Self::Unsendable(why) => why.clone(),
            Self::GuestStopped { step } => {
                format!("{step}: the guest stopped before it finished")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pure construction
// ---------------------------------------------------------------------------

/// Is this a name a POSIX shell can export?
///
/// `[A-Za-z_][A-Za-z0-9_]*`, and nothing else. Anything outside it is not an
/// assignable identifier in any shell, so `export 'my-var'=1` is a syntax error
/// rather than a variable — refusing here converts that into a message naming
/// the offending key.
pub(crate) fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("an environment variable name cannot be empty".to_string());
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('\0');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!(
            "env name `{name}` must start with a letter or underscore; a shell cannot assign it"
        ));
    }
    if let Some(bad) = chars.find(|c| !(c.is_ascii_alphanumeric() || *c == '_')) {
        return Err(format!(
            "env name `{name}` contains `{bad}`, which a shell cannot assign; \
             use letters, digits and underscores"
        ));
    }
    Ok(())
}

/// Parse one `--env KEY=VALUE`.
///
/// Splits on the *first* `=` so a value may contain any number more, which
/// matters for the things people actually put in env vars — connection strings,
/// base64, `PATH`-like lists.
pub(crate) fn parse_assignment(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(format!(
            "--env expects KEY=VALUE, got `{raw}` (an empty value is written `{raw}=`)"
        ));
    };
    validate_name(name)?;
    Ok((name.to_string(), value.to_string()))
}

/// The shell fragment that exports `env` in the caller's own shell.
///
/// Returns `None` for an empty map so the caller sends nothing rather than
/// framing a no-op.
pub(crate) fn export_fragment(env: &BTreeMap<String, String>) -> Option<String> {
    if env.is_empty() {
        return None;
    }
    let mut parts = Vec::with_capacity(env.len());
    for (k, v) in env {
        // The name is an identifier by construction (validated on the way in),
        // so it needs no quoting; the value is arbitrary and always gets it.
        parts.push(format!("{k}={}", exec::shell_quote(v)));
    }
    Some(format!("export {}", parts.join(" ")))
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// The console, as delivery needs to see it.
///
/// An interface rather than a concrete console so the sequencing above can be
/// tested against a scripted guest — including the guest that never answers,
/// which is the case worth having a test for and the one hardware cannot be
/// asked to reproduce on demand.
pub(crate) trait Console {
    /// Write bytes to the guest's serial input.
    fn send(&self, bytes: &[u8]);
    /// Console text produced since the run began, oldest first.
    fn transcript(&self) -> String;
    /// Has the guest stopped?
    fn stopped(&self) -> bool;
}

/// Deliver `plan` into a guest, in order: readiness, then `env`, then the
/// post-boot command.
///
/// The order is not arbitrary. `env` is exported *before* the command runs, so a
/// `postBootCommand` that reads a variable the same spec set sees it — otherwise
/// the two fields would be independently correct and jointly useless.
pub(crate) fn deliver(
    console: &dyn Console,
    plan: &Plan,
    ready_timeout: Duration,
    step_timeout: Duration,
) -> Result<Report, Failure> {
    if plan.is_empty() {
        return Ok(Report::NothingToDo);
    }

    let began = Instant::now();
    wait_ready(console, ready_timeout)?;

    if let Some(fragment) = export_fragment(&plan.env) {
        run_step(console, "env", &fragment, step_timeout)?;
    }

    let post_boot_code = match &plan.post_boot {
        None => None,
        Some(argv) => {
            let fragment = argv
                .iter()
                .map(|a| exec::shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            Some(run_step(
                console,
                "postBootCommand",
                &fragment,
                step_timeout,
            )?)
        }
    };

    let _ = began;
    Ok(Report::Delivered {
        exported: plan.env.len(),
        post_boot_code,
    })
}

/// Probe until a shell answers, or the deadline passes.
///
/// Records enough to *diagnose* the failure rather than merely report it: how
/// many probes went out, and whether the console ever produced any output at
/// all. The transcript is compared against its length at entry, so growth means
/// the guest emitted something — an echo of our own probe is enough, and is
/// exactly the signal that separates "nothing is listening on this console"
/// from "something is listening and cannot answer" (#273).
fn wait_ready(console: &dyn Console, timeout: Duration) -> Result<(), Failure> {
    let began = Instant::now();
    let at_entry = console.transcript().len();
    let mut probes = 0usize;
    loop {
        if console.stopped() {
            return Err(Failure::GuestStopped {
                step: "waiting for a shell".to_string(),
            });
        }
        // A fresh nonce per probe: a stale marker from an earlier probe that the
        // guest answered late must not be read as this one succeeding. This is
        // the load-bearing half, and it has its own tests; slicing the
        // transcript from `mark` below is defence in depth, and deliberately
        // recorded as such rather than credited with protection it does not
        // add — a mutation that removes it does not fail a single test, which
        // is exactly the signal that it is not the guard.
        let nonce = Nonce::mint();
        let line = exec::frame(&nonce, "true").map_err(Failure::Unsendable)?;
        let mark = console.transcript().len();
        send_line(console, &line);
        probes += 1;
        let until = Instant::now() + PROBE_INTERVAL;
        while Instant::now() < until {
            let full = console.transcript();
            let since = &full[mark.min(full.len())..];
            if let ExecOutcome::Completed { .. } = exec::parse(&nonce, since) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }

        if began.elapsed() >= timeout {
            return Err(Failure::NeverReady {
                waited: began.elapsed(),
                probes,
                echoed: console.transcript().len() > at_entry,
            });
        }
    }
}

/// Send one framed fragment and wait for its verdict.
fn run_step(
    console: &dyn Console,
    step: &str,
    fragment: &str,
    timeout: Duration,
) -> Result<i32, Failure> {
    let nonce = Nonce::mint();
    let line = exec::frame(&nonce, fragment).map_err(Failure::Unsendable)?;
    let mark = console.transcript().len();
    send_line(console, &line);

    let deadline = Instant::now() + timeout;
    loop {
        let full = console.transcript();
        let since = &full[mark.min(full.len())..];
        match exec::parse(&nonce, since) {
            ExecOutcome::Completed { code, output } => {
                if code == 0 {
                    return Ok(code);
                }
                return Err(Failure::Failed {
                    step: step.to_string(),
                    code,
                    output,
                });
            }
            ExecOutcome::Truncated => {
                return Err(Failure::NoVerdict {
                    step: step.to_string(),
                    detail: "its output was evicted from the console buffer before it was read"
                        .to_string(),
                });
            }
            ExecOutcome::Overflowed => {
                return Err(Failure::NoVerdict {
                    step: step.to_string(),
                    detail: "it produced more output than the console buffer holds".to_string(),
                });
            }
            ExecOutcome::Pending => {}
        }
        if console.stopped() {
            return Err(Failure::GuestStopped {
                step: step.to_string(),
            });
        }
        if Instant::now() >= deadline {
            return Err(Failure::NoVerdict {
                step: step.to_string(),
                detail: format!("it did not finish within {}s", timeout.as_secs()),
            });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// A carriage return is what a real terminal sends; the guest tty's ICRNL turns
/// it into the newline that completes the line.
/// Send one framed line to the guest console, after clearing whatever state the
/// last line left behind.
///
/// The frame assumes it lands on a shell at `PS1`. That assumption failed
/// (#273): a probe arrived truncated mid-quote --- `# ecf0' 'BEG'; ...` --- and
/// the unbalanced quote put the shell into a `PS2` continuation, where the next
/// 60 probes were read as *more of that same command* rather than executed. One
/// mangled write cost the entire run, and the probe loop could not recover,
/// because every recovery attempt became continuation text too.
///
/// So lead with `ETX`. Why that is the only reset that can work regardless of
/// the shell's current state, and why it must be a separate write, is documented
/// on [`exec::console_writes`].
///
/// Nothing of ours is ever running when this is sent: `send_line` is only called
/// to *begin* a step, and every step is awaited before the next is sent. The
/// signal can therefore only reach a process the guest started on its own
/// console, which is precisely the state we are trying to clear.
fn send_line(console: &dyn Console, line: &str) {
    for write in exec::console_writes(line) {
        console.send(&write);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::exec::ETX;

    // -- names and assignments ------------------------------------------------

    #[test]
    fn a_name_a_shell_cannot_assign_is_refused_by_name() {
        // Each of these would become a shell *syntax error* rather than a
        // variable, so `export` would fail and, in a subshell, fail invisibly.
        for bad in ["my-var", "1FOO", "a b", "FOO="] {
            let e = validate_name(bad).unwrap_err();
            assert!(
                e.contains(bad),
                "message should quote the offending name: {e}"
            );
        }
        assert!(validate_name("").is_err());
    }

    #[test]
    fn ordinary_names_are_accepted_including_leading_underscore() {
        for ok in ["FOO", "_", "_x9", "LANG", "PATH", "a1_B2"] {
            assert!(validate_name(ok).is_ok(), "{ok} should be assignable");
        }
    }

    #[test]
    fn an_assignment_splits_on_the_first_equals_so_values_may_contain_more() {
        let (k, v) = parse_assignment("DSN=postgres://u:p@h/db?opt=1").unwrap();
        assert_eq!(k, "DSN");
        assert_eq!(v, "postgres://u:p@h/db?opt=1");
    }

    #[test]
    fn an_empty_value_is_a_value_and_not_an_error() {
        // `FOO=` is a real, meaningful assignment; treating it as malformed
        // would make an intentional empty string unexpressible.
        let (k, v) = parse_assignment("FOO=").unwrap();
        assert_eq!(k, "FOO");
        assert_eq!(v, "");
    }

    #[test]
    fn an_assignment_with_no_equals_says_how_to_write_an_empty_value() {
        let e = parse_assignment("FOO").unwrap_err();
        assert!(e.contains("KEY=VALUE"), "{e}");
        assert!(e.contains("FOO="), "should show the empty-value form: {e}");
    }

    // -- the export fragment --------------------------------------------------

    #[test]
    fn an_empty_environment_sends_nothing_rather_than_framing_a_no_op() {
        assert_eq!(export_fragment(&BTreeMap::new()), None);
    }

    #[test]
    fn a_value_that_looks_like_shell_syntax_survives_a_real_shell_as_data() {
        // String-matching the quoting proves nothing useful — the interesting
        // question is what a shell *does* with it. So ask one. If the quoting
        // were wrong this would either fail to round-trip or run `id`.
        let hostile = "a'b; rm -rf /; $(id) `id` \"x\" \\ $HOME\nnewline\ttab";
        let mut env = BTreeMap::new();
        env.insert("FOO".to_string(), hostile.to_string());
        let frag = export_fragment(&env).unwrap();

        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{frag}; printf '%s' \"$FOO\""))
            .output()
            .expect("running /bin/sh");
        assert!(out.status.success(), "shell rejected: {frag}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            hostile,
            "the value must arrive byte-for-byte, not partly executed"
        );
    }

    #[test]
    fn a_hostile_value_cannot_smuggle_a_second_command_past_the_framing() {
        // The specific attack the quoting exists to stop: closing our quote and
        // appending a command of the caller's choosing.
        let mut env = BTreeMap::new();
        env.insert("FOO".to_string(), "x'; echo PWNED; :'".to_string());
        let frag = export_fragment(&env).unwrap();
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{frag}; printf '%s' \"$FOO\""))
            .output()
            .expect("running /bin/sh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("PWNED\n"),
            "the payload was executed rather than assigned: {stdout}"
        );
        assert_eq!(stdout, "x'; echo PWNED; :'");
    }

    #[test]
    fn exports_are_emitted_in_a_stable_order() {
        // BTreeMap, so a diff of two runs does not depend on authoring order.
        let mut env = BTreeMap::new();
        env.insert("ZED".to_string(), "1".to_string());
        env.insert("ALPHA".to_string(), "2".to_string());
        assert_eq!(export_fragment(&env).unwrap(), "export ALPHA='2' ZED='1'");
    }

    // -- sequencing -----------------------------------------------------------

    /// A guest that answers every framed line with a scripted exit status.
    struct FakeGuest {
        /// Exit codes to hand out, in order; the last repeats.
        codes: Mutex<Vec<i32>>,
        /// Lines the guest was sent, so ordering can be asserted.
        seen: Mutex<Vec<String>>,
        transcript: Mutex<String>,
        /// Ignore this many lines before answering anything, to model a guest
        /// that is still booting.
        deaf_for: Mutex<usize>,
        /// Deliver this many of the next writes only half-written, to model the
        /// console truncation behind #273.
        truncate_next: Mutex<usize>,
        /// Set when a truncated write left the shell mid-command. While it is
        /// set every further line is swallowed as continuation text.
        continuation: Mutex<bool>,
        stopped: Mutex<bool>,
    }

    impl FakeGuest {
        fn new(codes: Vec<i32>) -> Self {
            Self {
                codes: Mutex::new(codes),
                seen: Mutex::new(Vec::new()),
                transcript: Mutex::new(String::new()),
                deaf_for: Mutex::new(0),
                truncate_next: Mutex::new(0),
                continuation: Mutex::new(false),
                stopped: Mutex::new(false),
            }
        }
        fn deaf(mut self, n: usize) -> Self {
            self.deaf_for = Mutex::new(n);
            self
        }
        /// Truncate the next `n` writes, so they leave the shell mid-command.
        fn truncating(mut self, n: usize) -> Self {
            self.truncate_next = Mutex::new(n);
            self
        }
        fn commands(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Console for FakeGuest {
        fn send(&self, bytes: &[u8]) {
            // Ctrl-C. A real shell abandons whatever line it was assembling,
            // prints a fresh prompt, and answers no frame. Modelled before
            // anything else because that is the point of it: it must work
            // regardless of what state the shell is in.
            //
            // A console nobody is listening to loses the signal exactly as it
            // loses everything else -- and without consuming `deaf_for`, which
            // counts *commands* swallowed, not writes.
            if bytes.contains(&ETX) {
                if *self.deaf_for.lock().unwrap() > 0 {
                    return;
                }
                *self.continuation.lock().unwrap() = false;
                self.transcript.lock().unwrap().push_str("^C\n$ ");
                return;
            }
            let line = String::from_utf8_lossy(bytes).to_string();
            self.seen.lock().unwrap().push(line.clone());
            let mut deaf = self.deaf_for.lock().unwrap();
            if *deaf > 0 {
                *deaf -= 1;
                // A shell that is not listening loses the bytes entirely.
                return;
            }
            drop(deaf);

            // #273: the console accepted only part of the write. The shell has
            // half a command line and is waiting for the rest of it, so this
            // line and every line after it is continuation text, not a command.
            //
            // Deliberately modelled as "the write was cut" rather than by
            // counting quotes: `shell_quote` legitimately emits an odd number
            // of `'` when escaping an apostrophe, so a quote-counting fake
            // would invent a failure the real shell does not have.
            let mut trunc = self.truncate_next.lock().unwrap();
            if *trunc > 0 {
                *trunc -= 1;
                drop(trunc);
                *self.continuation.lock().unwrap() = true;
                let half = line.len() / 2;
                self.transcript.lock().unwrap().push_str(&line[..half]);
                return;
            }
            drop(trunc);
            if *self.continuation.lock().unwrap() {
                // Swallowed as more of the unfinished command: echoed, never run.
                self.transcript.lock().unwrap().push_str(&line);
                return;
            }

            // Recover the nonce from the line we were just sent and answer it
            // exactly as a real shell would: echo, then the joined markers.
            let nonce = line
                .split('\'')
                .find(|s| s.starts_with("chm"))
                .unwrap_or("chm")
                .to_string();
            let code = {
                let mut codes = self.codes.lock().unwrap();
                if codes.len() > 1 {
                    codes.remove(0)
                } else {
                    codes[0]
                }
            };
            let mut t = self.transcript.lock().unwrap();
            t.push_str(&line);
            t.push_str(&format!("\n{nonce}BEG\nsome output\n{nonce}END:{code}\n"));
        }
        fn transcript(&self) -> String {
            self.transcript.lock().unwrap().clone()
        }
        fn stopped(&self) -> bool {
            *self.stopped.lock().unwrap()
        }
    }

    fn plan(env: &[(&str, &str)], post: Option<&[&str]>) -> Plan {
        Plan {
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            post_boot: post.map(|p| p.iter().map(|s| s.to_string()).collect()),
        }
    }

    #[test]
    fn nothing_asked_for_means_nothing_sent_and_no_waiting() {
        let guest = FakeGuest::new(vec![0]);
        let r = deliver(
            &guest,
            &Plan::default(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert_eq!(r.unwrap(), Report::NothingToDo);
        // Load-bearing: a run with no spec must not be able to fail a probe it
        // never needed.
        assert!(guest.commands().is_empty());
    }

    #[test]
    fn env_is_exported_before_the_post_boot_command_runs() {
        let guest = FakeGuest::new(vec![0]);
        let r = deliver(
            &guest,
            &plan(&[("FOO", "bar")], Some(&["echo", "hi"])),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            r,
            Report::Delivered {
                exported: 1,
                post_boot_code: Some(0)
            }
        );
        let cmds = guest.commands();
        let export_at = cmds.iter().position(|c| c.contains("export FOO=")).unwrap();
        let post_at = cmds.iter().position(|c| c.contains("'echo' 'hi'")).unwrap();
        // Otherwise a postBootCommand reading a variable the same spec set would
        // not see it: both fields correct, jointly useless.
        assert!(export_at < post_at, "env must be exported first: {cmds:?}");
    }

    #[test]
    fn a_failing_post_boot_command_is_a_failure_and_carries_its_output() {
        // "Probably: fail the start, loudly. A sandbox whose setup command
        // failed is not the sandbox that was asked for." (#190)
        let guest = FakeGuest::new(vec![0, 0, 3]);
        let e = deliver(
            &guest,
            &plan(&[("FOO", "bar")], Some(&["false"])),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap_err();
        match &e {
            Failure::Failed { step, code, .. } => {
                assert_eq!(step, "postBootCommand");
                assert_eq!(*code, 3);
            }
            other => panic!("expected a failure carrying the exit status, got {other:?}"),
        }
        assert!(e.message().contains("exited 3"), "{}", e.message());
    }

    #[test]
    fn a_guest_that_never_answers_is_never_reported_as_delivered() {
        let guest = FakeGuest::new(vec![0]).deaf(usize::MAX);
        let e = deliver(
            &guest,
            &plan(&[("FOO", "bar")], None),
            Duration::from_millis(600),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(e, Failure::NeverReady { .. }), "{e:?}");
        // The whole point: silence is not success.
        assert!(
            e.message().contains("could not be delivered"),
            "{}",
            e.message()
        );
    }

    #[test]
    fn a_guest_that_is_slow_to_reach_a_shell_is_waited_for_rather_than_failed() {
        // Two probes are swallowed, as they would be by a guest still booting.
        let guest = FakeGuest::new(vec![0]).deaf(2);
        let r = deliver(
            &guest,
            &plan(&[("LANG", "C.UTF-8")], None),
            Duration::from_secs(10),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            r,
            Report::Delivered {
                exported: 1,
                post_boot_code: None
            }
        );
    }

    #[test]
    fn each_probe_carries_a_fresh_nonce() {
        // A stale marker answered late must not be read as the next probe
        // succeeding, which is only true if the nonce changes every time.
        let guest = FakeGuest::new(vec![0]).deaf(3);
        let _ = deliver(
            &guest,
            &plan(&[("A", "1")], None),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        let cmds = guest.commands();
        let probes: Vec<&String> = cmds.iter().filter(|c| c.contains("{ true ; }")).collect();
        assert!(probes.len() >= 2, "expected repeated probes: {cmds:?}");
        assert_ne!(probes[0], probes[1], "a probe must not reuse its nonce");
    }

    /// Each step's verdict must be its own.
    ///
    /// The readiness probe and `env` both answer 0 here and the post-boot
    /// command answers 3. If a step could match an *earlier* step's end marker
    /// — a shared nonce, or a scan that started before this step was sent — the
    /// failing command would be reported as the success in front of it, which is
    /// precisely the "exited 0 and did nothing" shape this whole module exists
    /// to prevent.
    #[test]
    fn a_later_step_never_inherits_an_earlier_steps_exit_code() {
        let guest = FakeGuest::new(vec![0, 0, 3]);
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "1".to_string());
        let plan = Plan {
            env,
            post_boot: Some(vec!["false".to_string()]),
        };
        let err = deliver(
            &guest,
            &plan,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect_err("a failing post-boot command must not be reported as success");
        match err {
            Failure::Failed { step, code, .. } => {
                assert_eq!(step, "postBootCommand");
                assert_eq!(code, 3);
            }
            other => panic!("wrong failure: {other:?}"),
        }
    }

    /// And the mirror: every step gets a nonce nobody else used, so the
    /// protection above does not rest on scan windows alone.
    #[test]
    fn every_framed_step_carries_its_own_nonce() {
        let guest = FakeGuest::new(vec![0]);
        let mut env = BTreeMap::new();
        env.insert("A".to_string(), "1".to_string());
        let plan = Plan {
            env,
            post_boot: Some(vec!["true".to_string()]),
        };
        deliver(
            &guest,
            &plan,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("delivery");

        let nonces: Vec<String> = guest
            .commands()
            .iter()
            .filter_map(|l| {
                l.split('\'')
                    .find(|s| s.starts_with("chm"))
                    .map(str::to_string)
            })
            .collect();
        assert!(nonces.len() >= 3, "probe + env + command: {nonces:?}");
        let mut sorted = nonces.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), nonces.len(), "a nonce was reused: {nonces:?}");
    }

    // -- recovering from a mangled write (#273) --------------------------------

    /// **The bug in #273.** One probe arrived truncated, its unbalanced quote
    /// put the shell into a `PS2` continuation, and all 60+ later probes were
    /// swallowed as more of that unfinished command. The run spent its whole
    /// life probing a shell that could never answer, and the state that made it
    /// impossible was created by the very first probe.
    ///
    /// The guard is that recovery must not depend on the *next* write being
    /// clean, because the next write lands in the same poisoned state. It has to
    /// clear the state first.
    #[test]
    fn a_truncated_probe_cannot_poison_the_probes_after_it() {
        let guest = FakeGuest::new(vec![0]).truncating(1);
        wait_ready(&guest, Duration::from_secs(3)).expect(
            "the first probe was cut mid-line and every probe after it was swallowed as \
             continuation text -- one mangled write cost the whole run (#273)",
        );
    }

    /// The mirror: a console that stays broken must still *fail*, or the test
    /// above would pass with a `wait_ready` that never checks anything.
    #[test]
    fn a_console_that_never_stops_mangling_still_fails() {
        let guest = FakeGuest::new(vec![0]).truncating(usize::MAX);
        let e = wait_ready(&guest, Duration::from_millis(600)).unwrap_err();
        assert!(
            matches!(e, Failure::NeverReady { .. }),
            "expected NeverReady, got {e:?}"
        );
    }

    /// Two silences that need opposite fixes must not read the same.
    ///
    /// "the guest has no getty on this console" and "a shell is here and is
    /// stuck mid-command" are one message today, and it names only the first.
    /// Whoever hits the second is told to check something that is already fine.
    #[test]
    fn a_silent_console_is_diagnosed_by_whether_it_ever_spoke() {
        // Nothing listening: the bytes are lost, so the transcript never grows.
        let quiet = FakeGuest::new(vec![0]).deaf(usize::MAX);
        let e = wait_ready(&quiet, Duration::from_millis(600)).unwrap_err();
        let Failure::NeverReady { echoed, probes, .. } = &e else {
            panic!("expected NeverReady, got {e:?}");
        };
        assert!(!echoed, "a console that lost every byte cannot have echoed");
        assert!(*probes >= 1, "no probe was counted");
        let m = e.message();
        assert!(
            m.contains("no output at all") && m.contains("getty"),
            "a console nothing is listening to must say so: {m}"
        );

        // Listening but wedged: our own bytes come back, no frame ever does.
        let wedged = FakeGuest::new(vec![0]).truncating(usize::MAX);
        let e = wait_ready(&wedged, Duration::from_millis(600)).unwrap_err();
        let Failure::NeverReady { echoed, .. } = &e else {
            panic!("expected NeverReady, got {e:?}");
        };
        assert!(echoed, "the guest echoed the truncated line back");
        let m = e.message();
        assert!(
            m.contains("did produce output") && m.contains("mid-command"),
            "a wedged shell must be named as one: {m}"
        );
    }
}
