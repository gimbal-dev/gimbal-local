// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Run a command in a running sandbox and learn whether it worked.
//!
//! Until this module the only way to make a guest do something was `chm ctl
//! input`, which types characters at a serial console and leaves the caller to
//! scrape the screen and guess. There was no exit code, no output boundary, and
//! no way to tell "the command failed" from "the command has not finished yet".
//!
//! # The transport is the console, and that is deliberate
//!
//! A guest agent reached over vsock would give real streams and process
//! identity, but it needs software *inside* the guest, which would restrict this
//! to images we build. The console is the one channel every image already has,
//! including a bring-your-own image we have never seen, so this framing runs on
//! anything with a shell. Nothing in the [`ExecRequest`] / [`ExecOutcome`] shape
//! is console-specific: a later vsock transport can replace [`script`] and
//! [`parse`] without the caller noticing.
//!
//! # Framing
//!
//! [`script`] emits, for a per-exec random `nonce`:
//!
//! ```text
//! printf '%s%s\n' 'NONCE' 'BEG'; { <argv> ; } 2>&1; __chm_rc=$?; printf '%s%s:%d\n' 'NONCE' 'END' "$__chm_rc"
//! ```
//!
//! The shell **echoes** that line back before running it, so the console
//! contains the marker text twice. The two are told apart structurally rather
//! than by guessing: the echo holds `NONCE` and `BEG` as *separate* `printf`
//! arguments and never their concatenation, while the executed `printf` emits
//! `NONCEBEG` joined. Matching the joined form therefore cannot match the echo,
//! whatever the shell's echo settings are.
//!
//! # What a hostile guest can and cannot do
//!
//! It can lie about the command's exit status — it is the thing running the
//! command, so no transport changes that. What it must never be able to do is
//! make a *transport* failure look like success, so:
//!
//! - the `nonce` is minted per exec from the system CSPRNG, so console content
//!   that predates the request cannot match the end marker;
//! - [`parse`] returns [`ExecOutcome::Completed`] **only** on a well-formed end
//!   marker, and every other path is a distinct non-success variant;
//! - eviction from the console ring is detected and reported as
//!   [`ExecOutcome::Truncated`] rather than silently returning the wrong bytes.

use std::{fmt, process, str};

use ring::rand::{SecureRandom, SystemRandom};

/// Marker suffix printed before the command's output.
const BEGIN: &str = "BEG";
/// Marker suffix printed after it, carrying the exit status.
const END: &str = "END";

/// How much of the console a single exec may accumulate before we stop waiting
/// and report [`ExecOutcome::Overflowed`]. Well below the daemon's 256 KiB ring
/// so a large-output command is reported honestly rather than silently clipped
/// by eviction.
pub(crate) const MAX_OUTPUT: usize = 128 * 1024;

/// Longest script line the guest's terminal can accept.
///
/// A Linux tty in canonical mode buffers an unterminated line in `N_TTY_BUF_SIZE`
/// (4096 bytes) and **silently discards** everything past it, so an over-long
/// command would not fail — it would arrive mangled and then time out with no
/// indication why. Refusing up front turns that into a clear error. The headroom
/// covers the line terminator and the framing we add around the argv.
pub(crate) const MAX_SCRIPT: usize = 4000;

/// A per-exec framing token. Random, so console bytes written before the request
/// cannot be mistaken for its end marker.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Nonce(String);

impl Nonce {
    /// Mint a nonce from the system CSPRNG.
    ///
    /// The `chm` prefix keeps it recognisable in a console transcript. Falls
    /// back to a pid/address-derived value only if the CSPRNG is unavailable,
    /// which is not a security boundary here: the nonce separates our own output
    /// from surrounding console noise, and a guest able to observe it already
    /// controls everything it frames.
    pub(crate) fn mint() -> Self {
        let mut bytes = [0u8; 8];
        if SystemRandom::new().fill(&mut bytes).is_err() {
            let seed = process::id() as u64 ^ (&bytes as *const _ as u64);
            bytes = seed.to_le_bytes();
        }
        let mut s = String::with_capacity(3 + bytes.len() * 2);
        s.push_str("chm");
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        Self(s)
    }

    /// The marker the guest prints immediately *before* the command's output.
    fn begin_marker(&self) -> String {
        format!("{}{BEGIN}", self.0)
    }

    /// The prefix of the marker printed *after* it; the exit status follows.
    fn end_prefix(&self) -> String {
        format!("{}{END}:", self.0)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.0)
    }
}

/// Quote one argument for a POSIX shell.
///
/// Single quotes suppress every form of expansion, so the only character needing
/// care is `'` itself, which is closed, escaped, and reopened. Applied to every
/// argument without exception: the caller passes an argv, and nothing in it is
/// ever interpreted as shell syntax (invariant I5 — explicit quoting, no
/// implicit interpretation of caller-supplied text).
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Build the shell line that runs `argv` and frames its output.
///
/// `argv` is an argv, not a command *line*: no element is ever parsed as shell
/// syntax. To use a shell deliberately, pass one — `["bash", "-lc", "a | b"]` —
/// so that the decision is visible at the call site instead of being an implicit
/// property of whether the string happened to contain a metacharacter.
///
/// Returns `Err` for an empty argv, which would otherwise frame and time out on
/// a command that was never sent.
pub(crate) fn script(nonce: &Nonce, argv: &[String]) -> Result<String, String> {
    if argv.is_empty() {
        return Err("no command given".to_string());
    }
    let cmd = argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    // `%s%s` keeps the nonce and the marker word separate in the echoed text and
    // joined only in the printed text; see the module docs.
    let line = format!(
        "printf '%s%s\\n' {n} '{BEGIN}'; {{ {cmd} ; }} 2>&1; __chm_rc=$?; \
         printf '%s%s:%d\\n' {n} '{END}' \"$__chm_rc\"",
        n = shell_quote(&nonce.0),
        cmd = cmd,
    );
    if line.len() > MAX_SCRIPT {
        return Err(format!(
            "command is too long for a guest terminal ({} bytes of framed input, limit {MAX_SCRIPT}); \
             put it in a script and run that instead",
            line.len()
        ));
    }
    Ok(line)
}

/// Encode an argv for the daemon's line-oriented control protocol.
///
/// Hex rather than an escape scheme: an argument may contain any byte at all,
/// including the space and newline the protocol uses as delimiters, and a
/// quoting scheme that has to round-trip those is a bug waiting to happen at
/// exactly the boundary where correctness matters most.
///
/// An *empty* argument is a real argument — `grep '' file` is not `grep file` —
/// but it hexes to nothing and would be swallowed by the field split, so it
/// travels as `-`, which no hex encoding can produce.
pub(crate) fn encode_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() {
                "-".to_string()
            } else {
                a.bytes().map(|b| format!("{b:02x}")).collect::<String>()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode an argv produced by [`encode_argv`].
pub(crate) fn decode_argv(wire: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for word in wire.split_whitespace() {
        if word == "-" {
            out.push(String::new());
            continue;
        }
        if word.len() % 2 != 0 {
            return Err("malformed argument encoding".to_string());
        }
        let mut bytes = Vec::with_capacity(word.len() / 2);
        for pair in word.as_bytes().chunks(2) {
            let s = str::from_utf8(pair).map_err(|_| "malformed argument encoding")?;
            bytes.push(u8::from_str_radix(s, 16).map_err(|_| "malformed argument encoding")?);
        }
        out.push(String::from_utf8(bytes).map_err(|_| "argument is not valid UTF-8")?);
    }
    Ok(out)
}

/// What became of an exec request.
///
/// Every variant except [`Completed`](ExecOutcome::Completed) is a failure to
/// *obtain* a verdict, and is deliberately not collapsible into an exit status —
/// a caller cannot accidentally read "we never heard back" as "it worked".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExecOutcome {
    /// The end marker was seen. `code` is the guest's exit status, and `output`
    /// is everything between the markers.
    Completed { code: i32, output: String },
    /// The command is still running: no end marker yet.
    Pending,
    /// Output was evicted from the console ring before it could be read, so what
    /// remains is not the command's full output and is not reported as if it
    /// were.
    Truncated,
    /// The command produced more than [`MAX_OUTPUT`] bytes without finishing.
    Overflowed,
}

/// Extract an outcome from the console bytes captured since the request was
/// sent.
///
/// `since` is the console text from the moment the command was written. It still
/// contains the shell's echo of the command line, which is discarded by matching
/// the *joined* marker form (see the module docs).
pub(crate) fn parse(nonce: &Nonce, since: &str) -> ExecOutcome {
    let begin = nonce.begin_marker();
    let end = nonce.end_prefix();

    let Some(b) = since.find(&begin) else {
        // No begin marker yet. Overflow is only meaningful once the command is
        // known to have started; before that the bytes are the echo and any
        // unrelated console traffic.
        return if since.len() > MAX_OUTPUT {
            ExecOutcome::Overflowed
        } else {
            ExecOutcome::Pending
        };
    };
    let after_begin = &since[b + begin.len()..];
    // The marker is printed with a trailing newline; drop it so a command that
    // produced nothing yields an empty string rather than a stray blank line.
    let body_start = after_begin
        .strip_prefix("\r\n")
        .or_else(|| after_begin.strip_prefix('\n'));
    let body = body_start.unwrap_or(after_begin);

    let Some(e) = body.find(&end) else {
        return if body.len() > MAX_OUTPUT {
            ExecOutcome::Overflowed
        } else {
            ExecOutcome::Pending
        };
    };
    let digits: String = body[e + end.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        // The prefix is there but the status has not arrived yet: the guest is
        // mid-`printf`. Waiting is correct; guessing a status is not.
        return ExecOutcome::Pending;
    }
    let Ok(code) = digits.parse::<i32>() else {
        return ExecOutcome::Pending;
    };

    // Trim the newline the shell emitted just before the end marker.
    let mut output = &body[..e];
    for suffix in ["\r\n", "\n"] {
        if let Some(t) = output.strip_suffix(suffix) {
            output = t;
            break;
        }
    }
    ExecOutcome::Completed {
        code,
        output: normalize_newlines(output),
    }
}

/// Turn the tty's `CRLF` line endings back into plain newlines.
///
/// The guest's terminal applies `ONLCR` on the way out, so every line arrives
/// with a carriage return that the command never wrote. Leaving them in means a
/// caller splitting the JSON `output` on `\n` gets a trailing `\r` on every
/// line — a papercut on the machine-readable path, which is the one that
/// matters most here.
///
/// Only the *pair* is rewritten. A lone `\r` is how a program redraws a
/// progress line, so it is real output and is left alone.
fn normalize_newlines(s: &str) -> String {
    if s.contains("\r\n") {
        s.replace("\r\n", "\n")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> Nonce {
        Nonce("chmdeadbeef".to_string())
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn quotes_every_argument_including_shell_metacharacters() {
        let s = script(
            &nonce(),
            &argv(&["echo", "a; rm -rf /", "$(whoami)", "`id`"]),
        )
        .unwrap();
        // The dangerous text survives verbatim *inside* single quotes, which is
        // exactly the point: it reaches the command as data, not as syntax.
        assert!(s.contains("'a; rm -rf /'"), "{s}");
        assert!(s.contains("'$(whoami)'"), "{s}");
        assert!(s.contains("'`id`'"), "{s}");
    }

    #[test]
    fn embedded_single_quote_cannot_break_out() {
        let s = script(&nonce(), &argv(&["echo", "it's"])).unwrap();
        assert!(s.contains(r"'it'\''s'"), "{s}");
    }

    #[test]
    fn empty_argv_is_refused_rather_than_framed() {
        assert!(script(&nonce(), &[]).is_err());
    }

    #[test]
    fn the_echoed_command_line_never_contains_a_joined_marker() {
        // The whole disambiguation rests on this: what the shell echoes back is
        // the script text, and the script text must not contain the joined
        // markers that only the *executed* printf produces.
        let s = script(&nonce(), &argv(&["true"])).unwrap();
        assert!(
            !s.contains("chmdeadbeefBEG"),
            "echo would be mistaken for output start: {s}"
        );
        assert!(
            !s.contains("chmdeadbeefEND:"),
            "echo would be mistaken for completion: {s}"
        );
    }

    #[test]
    fn parses_output_and_exit_status() {
        let console = "chmdeadbeefBEG\nhello\nchmdeadbeefEND:0\n";
        assert_eq!(
            parse(&nonce(), console),
            ExecOutcome::Completed {
                code: 0,
                output: "hello".to_string()
            }
        );
    }

    #[test]
    fn parses_a_nonzero_status() {
        let console = "chmdeadbeefBEG\nnope\nchmdeadbeefEND:127\n";
        match parse(&nonce(), console) {
            ExecOutcome::Completed { code, .. } => assert_eq!(code, 127),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_command_with_no_output_yields_an_empty_string_not_a_blank_line() {
        let console = "chmdeadbeefBEG\nchmdeadbeefEND:0\n";
        assert_eq!(
            parse(&nonce(), console),
            ExecOutcome::Completed {
                code: 0,
                output: String::new()
            }
        );
    }

    #[test]
    fn tolerates_carriage_returns_from_the_tty() {
        let console = "chmdeadbeefBEG\r\nhi\r\nchmdeadbeefEND:0\r\n";
        assert_eq!(
            parse(&nonce(), console),
            ExecOutcome::Completed {
                code: 0,
                output: "hi".to_string()
            }
        );
    }

    /// The tty adds a carriage return to every line the command did not write.
    /// A caller splitting `output` on `\n` must not find them.
    #[test]
    fn interior_tty_line_endings_are_normalised() {
        let console = "chmdeadbeefBEG\r\na\r\nb\r\nc\r\nchmdeadbeefEND:0\r\n";
        assert_eq!(
            parse(&nonce(), console),
            ExecOutcome::Completed {
                code: 0,
                output: "a\nb\nc".to_string()
            }
        );
    }

    /// A lone carriage return is a program redrawing a line — real output, and
    /// not ours to rewrite.
    #[test]
    fn a_bare_carriage_return_is_left_alone() {
        let console = "chmdeadbeefBEG\r\n50%\r100%\r\nchmdeadbeefEND:0\r\n";
        match parse(&nonce(), console) {
            ExecOutcome::Completed { output, .. } => assert_eq!(output, "50%\r100%"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_shells_echo_of_the_command_is_not_mistaken_for_a_result() {
        // Exactly what the console holds a moment after writing: the echo, and
        // nothing else. A parser matching the nonce alone would report success.
        let echo = script(&nonce(), &argv(&["true"])).unwrap();
        assert_eq!(parse(&nonce(), &echo), ExecOutcome::Pending);
    }

    #[test]
    fn output_that_merely_mentions_the_nonce_does_not_end_the_command() {
        let console = "chmdeadbeefBEG\nsaw chmdeadbeef and chmdeadbeefEN\n";
        assert_eq!(parse(&nonce(), console), ExecOutcome::Pending);
    }

    #[test]
    fn a_half_written_end_marker_waits_rather_than_guessing() {
        let console = "chmdeadbeefBEG\nout\nchmdeadbeefEND:";
        assert_eq!(parse(&nonce(), console), ExecOutcome::Pending);
    }

    #[test]
    fn a_different_execs_marker_is_ignored() {
        let console = "chmdeadbeefBEG\nwork\nchmcafebabeEND:0\n";
        assert_eq!(parse(&nonce(), console), ExecOutcome::Pending);
    }

    #[test]
    fn unfinished_output_past_the_cap_overflows_rather_than_hanging() {
        let mut console = String::from("chmdeadbeefBEG\n");
        console.push_str(&"x".repeat(MAX_OUTPUT + 1));
        assert_eq!(parse(&nonce(), &console), ExecOutcome::Overflowed);
    }

    #[test]
    fn console_noise_before_the_begin_marker_is_discarded() {
        let console = "[  12.345] random kernel chatter\nchmdeadbeefBEG\nmine\nchmdeadbeefEND:3\n";
        assert_eq!(
            parse(&nonce(), console),
            ExecOutcome::Completed {
                code: 3,
                output: "mine".to_string()
            }
        );
    }

    #[test]
    fn minted_nonces_differ() {
        assert_ne!(Nonce::mint().0, Nonce::mint().0);
    }

    #[test]
    fn an_over_long_command_is_refused_rather_than_silently_truncated_by_the_tty() {
        // A guest tty drops the tail of an over-long canonical-mode line, so
        // this would otherwise arrive as a mangled command and time out with no
        // hint as to why.
        let big = "x".repeat(MAX_SCRIPT);
        let err = script(&nonce(), &argv(&["echo", &big])).unwrap_err();
        assert!(err.contains("too long"), "{err}");
    }

    #[test]
    fn a_command_just_under_the_limit_is_accepted() {
        let s = script(&nonce(), &argv(&["echo", &"x".repeat(3800)])).unwrap();
        assert!(s.len() <= MAX_SCRIPT);
    }

    #[test]
    fn argv_round_trips_through_the_wire_encoding() {
        let original = argv(&["bash", "-lc", "echo 'hi there'\nsecond line", "", "é\t|&;"]);
        assert_eq!(decode_argv(&encode_argv(&original)).unwrap(), original);
    }

    /// An empty argument is an argument: `grep '' file` matches everything and
    /// `grep file` reads stdin. Dropping it would silently run a different
    /// command from the one asked for.
    #[test]
    fn an_empty_argument_survives_the_wire_and_reaches_the_shell() {
        assert_eq!(
            decode_argv(&encode_argv(&argv(&["a", "", "b"])))
                .unwrap()
                .len(),
            3
        );
        let s = script(&nonce(), &argv(&["grep", "", "f"])).unwrap();
        assert!(s.contains("'grep' '' 'f'"), "{s}");
    }

    #[test]
    fn a_malformed_wire_encoding_is_refused() {
        assert!(decode_argv("abc").is_err());
        assert!(decode_argv("zz").is_err());
    }

    #[test]
    fn a_minted_nonce_is_shell_safe() {
        // It is interpolated into the script, so it must contain nothing a shell
        // would act on even before quoting.
        let n = Nonce::mint();
        assert!(n.0.chars().all(|c| c.is_ascii_alphanumeric()), "{}", n.0);
    }
}
