// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Properties of the project's own gates, checked by the test suite.
//!
//! Everything here guards against a failure mode that is invisible to a normal
//! run: a test that fails once in hundreds of runs for reasons absent from its
//! own source, a lint gate that stops inspecting a whole category of code while
//! still exiting 0, or a document that advertises a form the tooling rejects.
//!
//! That class is worth its own module because it is the class we have actually
//! been bitten by, repeatedly, and because the cost of the bite is paid in hours
//! of someone else's time rather than in a user-visible defect. In every case
//! the suite stayed green while the thing it was trusted to police did not.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Every `.rs` file under `dir`.
    fn sources_under(dir: &Path) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, &mut out);
        out.sort();
        assert!(!out.is_empty(), "found no sources to scan; the walk is broken");
        out
    }

    /// Every `.rs` file under `chm/src`.
    fn sources() -> Vec<PathBuf> {
        sources_under(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
    }

    /// No two temporary paths keyed by `process::id()` may share a prefix.
    ///
    /// **`process::id()` does not distinguish tests.** Every `#[test]` in this
    /// binary runs as a thread inside one process, so the value is identical for
    /// all of them. A prefix used by two tests therefore names *one directory*
    /// that both of them create, write, and `remove_dir_all` — concurrently.
    ///
    /// The failure that produces is not a wrong answer, it is a rare one: the
    /// tests have to overlap, which depends on scheduling, so it shows up as a
    /// single unexplained failure in a run of several hundred and then refuses
    /// to reproduce. #243 is exactly that, and 33 clean reruns could say nothing
    /// about it.
    ///
    /// Demonstrated rather than assumed: `chm-peer-{pid}` was shared by
    /// `serve::peer_uid_matches_this_user_over_a_local_socket` and
    /// `state_cdn::peer_cache_serves_held_chunks_and_404s_misses`. Widening the
    /// window with a 300ms sleep made the second fail deterministically — its
    /// cached chunk read back 404 instead of 200, because the first test's
    /// opening `remove_dir_all` had deleted it. A narrower version of that race
    /// is live in every run.
    ///
    /// #243 recorded that this class *had* been checked. It had — for two
    /// specific prefixes that were already suspected. An audit scoped to the
    /// names you already suspect cannot find the collision you do not, which is
    /// why this is a scan of all of them and not a list.
    #[test]
    fn no_two_tests_share_a_process_id_keyed_temp_path() {
        // The prefix is the literal immediately before `{}` in a format string
        // whose only argument is `process::id()`.
        let mut owners: HashMap<String, Vec<String>> = HashMap::new();
        for path in sources() {
            let text = fs::read_to_string(&path).expect("read source");
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            for line in text.lines() {
                if !line.contains("process::id()") {
                    continue;
                }
                let Some(open) = line.find("format!(\"") else {
                    continue;
                };
                let rest = &line[open + "format!(\"".len()..];
                let Some(close) = rest.find('"') else {
                    continue;
                };
                let template = &rest[..close];
                // Only single-placeholder templates name a whole directory; a
                // second placeholder (a timestamp, say) already disambiguates.
                if template.matches("{}").count() != 1 {
                    continue;
                }
                let Some(prefix) = template.split("{}").next() else {
                    continue;
                };
                if prefix.is_empty() {
                    continue;
                }
                owners.entry(prefix.to_string()).or_default().push(file.clone());
            }
        }

        let shared: Vec<_> = owners
            .iter()
            .filter(|(_, sites)| sites.len() > 1)
            .map(|(prefix, sites)| format!("`{prefix}{{pid}}` used by {sites:?}"))
            .collect();
        assert!(
            shared.is_empty(),
            "these temp paths are the same directory in every run, because \
             process::id() is identical across tests in one binary:\n  {}",
            shared.join("\n  ")
        );
    }

    /// The repository root, one level above `chm/`.
    fn repo_root() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("chm/ has a parent")
            .to_path_buf();
        assert!(root.join("Makefile").is_file(), "repo root is not where we think it is");
        root
    }

    /// `make clippy` must keep inspecting test code, *and* keep failing on it.
    ///
    /// #362: the gate linted production code only, so 1,168 test functions were
    /// never inspected. `--all-targets` alone does not fix it — the diagnostics
    /// that catch the historical bug (a duplicated `#[test]` silently replacing
    /// its neighbour) are *warn*-level, so the gate reported the defect and
    /// still exited 0. Both halves are load-bearing and neither is obviously
    /// so from reading the recipe, which is exactly why removing one is easy.
    #[test]
    fn the_lint_gate_still_inspects_test_code_and_fails_on_it() {
        let makefile = fs::read_to_string(repo_root().join("Makefile")).expect("read Makefile");

        // The recipe is the indented block under the `clippy:` target.
        let mut recipe = Vec::new();
        let mut inside = false;
        for line in makefile.lines() {
            if line.starts_with("clippy:") {
                inside = true;
                continue;
            }
            if inside {
                if line.starts_with('\t') {
                    recipe.push(line);
                } else if !line.trim().is_empty() {
                    break;
                }
            }
        }

        let invocations: Vec<&&str> =
            recipe.iter().filter(|l| l.contains("cargo clippy")).collect();
        assert!(
            !invocations.is_empty(),
            "found no `cargo clippy` invocation under the `clippy:` target; \
             this guard is reading the wrong thing and is not protecting anything"
        );

        for line in invocations {
            assert!(
                line.contains("--all-targets"),
                "this clippy invocation does not inspect test code, so tests can \
                 rot unseen (#362):\n  {}",
                line.trim()
            );
            assert!(
                line.contains("-D warnings"),
                "this clippy invocation reports problems but still exits 0, so it \
                 is not a gate (#362):\n  {}",
                line.trim()
            );
        }
    }

    /// Every commit prefix CONTRIBUTING.md advertises must be one gitlint takes.
    ///
    /// #335: the guide's worked examples included `hvf:` and `app:`, and the
    /// gitlint rule rejected both — so a contributor who copied the
    /// documentation exactly had their commit refused by the project's own
    /// linter. Nothing connected the two files, so the drift was free.
    #[test]
    fn contributing_only_advertises_prefixes_gitlint_accepts() {
        let root = repo_root();
        let doc = fs::read_to_string(root.join("CONTRIBUTING.md")).expect("read CONTRIBUTING.md");
        let rule = fs::read_to_string(
            root.join("scripts/gitlint/rules/TitleStartsWithComponent.py"),
        )
        .expect("read the gitlint rule");

        // The components the rule accepts, read out of its own tuple rather
        // than restated here — a restated list would drift the same way.
        let body = rule
            .split_once("valid_components = (")
            .expect("rule declares valid_components")
            .1
            .split_once(')')
            .expect("the tuple closes")
            .0;
        let accepted: Vec<String> = body
            .split('\'')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect();
        assert!(accepted.len() > 10, "parsed too few components: {accepted:?}");

        // The worked examples, taken from the fenced block the guide tells a
        // contributor to copy.
        let after = doc
            .split_once("component prefix")
            .expect("CONTRIBUTING explains the component prefix")
            .1;
        let fenced = after
            .split_once("```text")
            .expect("the examples are fenced")
            .1
            .split_once("```")
            .expect("the fence closes")
            .0;

        let mut advertised = Vec::new();
        for line in fenced.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((prefix, _)) = line.split_once(": ") else {
                continue;
            };
            for part in prefix.split(',') {
                advertised.push(part.trim().to_string());
            }
        }
        assert!(
            !advertised.is_empty(),
            "parsed no example commit subjects out of CONTRIBUTING.md; this \
             guard is reading the wrong block and is not protecting anything"
        );

        let rejected: Vec<&String> =
            advertised.iter().filter(|c| !accepted.contains(c)).collect();
        assert!(
            rejected.is_empty(),
            "CONTRIBUTING.md tells contributors to use these prefixes and the \
             gitlint rule refuses them, so following the guide fails the lint \
             (#335): {rejected:?}"
        );
    }

    /// Collapse every run of whitespace to a single space.
    ///
    /// Prose wraps. A claim reinstated across a line break is the same claim to
    /// a reader and a different string to `contains`, so a substring search over
    /// raw markdown sails straight past it. That is not hypothetical: the
    /// retraction guard in `cpu-feature-deltas.md` failed its own first mutation
    /// for exactly this reason.
    fn flattened(doc: &str) -> String {
        doc.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// `docs/first-resume.md` states what was measured, not what was assumed.
    ///
    /// This page is the one a user reads on their first rehydrated capture, so
    /// every sentence in it is an instruction someone will follow. Four of its
    /// claims were measured false on real hardware and each one made a working
    /// configuration worse:
    ///
    /// - it said `apt --fix-broken install` does not clear a half-applied
    ///   package database. It does, in one command, durably across a suspend and
    ///   resume (#343).
    /// - it prescribed overwriting `/etc/resolv.conf`, on captures whose
    ///   `systemd-resolved` is `active` and whose lookups return `rc=0`.
    /// - it prescribed `NODE_OPTIONS=--jitless` from figures taken before the
    ///   `SCTLR_EL1.UCT` fix (#290) moved `npm --version` from 5 of 20 to 20 of
    ///   20.
    /// - it routed anyone wanting a native agent binary to cold-boot instead of
    ///   rehydrating, which is the opposite of the thing this project exists to
    ///   make work — and which a rehydrated capture has since done.
    ///
    /// The absence half is the load-bearing half. A stale figure is not merely
    /// out of date, it is an argument for a workaround the reader does not need,
    /// and the way it comes back is by someone restoring a paragraph that reads
    /// perfectly well on its own.
    ///
    /// Deliberately asserts *claims*, not the mere presence of a command. #284
    /// is the standing lesson: a guard checking that four commands are named
    /// stayed green while they were named in an order that silently did nothing.
    #[test]
    fn the_first_resume_guide_says_what_was_measured() {
        let doc = flattened(include_str!("../../docs/first-resume.md"));

        // The cures, as measured. Each is a command a reader will paste.
        for needle in [
            "sudo apt --fix-broken install -y",
            "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
            "sudo sgdisk -e /dev/vda",
        ] {
            assert!(
                doc.contains(needle),
                "docs/first-resume.md no longer carries the measured cure \
                 `{needle}`, so the page has stopped telling a user the thing \
                 that was actually verified on hardware"
            );
        }

        // The findings those cures rest on. Without these the commands are
        // folklore a later reader cannot evaluate.
        for (needle, why) in [
            (
                "means run it again",
                "repairing the package state runs update-initramfs, which was \
                 measured segfaulting 3 times in 6 runs (#366); without the \
                 retry advice a user concludes the one-command cure does not \
                 work",
            ),
            (
                "captured RAM, not on the disk",
                "the broken package state is in the snapshot's RAM while the \
                 disk image is clean, which is why no host-side scan can ever \
                 detect it and why the durable fix is at capture time",
            ),
            (
                "graviton-capture-request.md",
                "the capture-time quiescence requirement is the actual cure; \
                 dropping the pointer leaves the guest-side repair looking like \
                 the whole answer",
            ),
            (
                "293 and 265 stale of 300",
                "#287's kernel-text repair is measured by its control arm; \
                 without the without-the-repair numbers the 0 of 300 is an \
                 observation rather than evidence that the repair did it",
            ),
            (
                "overwrite `/etc/resolv.conf`",
                "the page has to actively warn against its own former advice, \
                 because that advice replaces a working resolver configuration",
            ),
        ] {
            assert!(
                doc.contains(needle),
                "docs/first-resume.md no longer says `{needle}`: {why}"
            );
        }

        // Claims measured false. Each of these was in the document and each one
        // sent a reader somewhere worse than where they started.
        for (needle, why) in [
            (
                "does not clear it",
                "`apt --fix-broken install -y` was measured returning rc=0 and \
                 leaving `dpkg --audit` silent across a suspend and resume",
            ),
            (
                "10 times out of 10",
                "that npm figure predates the SCTLR_EL1.UCT fix (#290); the \
                 same command was measured 20 of 20 afterwards",
            ),
            (
                "5 runs out of 5",
                "that native-binary figure predates #290 as well, and a \
                 rehydrated capture has since run the Copilot CLI end to end",
            ),
            (
                "profile.d/jitless.sh",
                "prescribing --jitless for every session is a pre-emptive \
                 workaround for a bug that was fixed; it also breaks under \
                 sudo, which strips NODE_OPTIONS (#289)",
            ),
            (
                "nodejs.org/dist",
                "bypassing apt with an upstream tarball was the workaround for \
                 a package database that turned out to be repairable in one \
                 command",
            ),
            (
                "no platform package found",
                "that #261 symptom belonged to the pre-#290 stride bug; \
                 reporting it as a live limitation sends readers to cold boot",
            ),
        ] {
            assert!(
                !doc.contains(needle),
                "docs/first-resume.md has `{needle}` back in it: {why}"
            );
        }
    }

    /// The first-resume guide must name the tags the hypervisor really prints.
    ///
    /// #310's whole point is that a reader who sees `[stall]` on their console
    /// can tell it apart from `[wedge]` without reading hypervisor source. That
    /// only holds while the page and the code agree, and they live in different
    /// crates -- so the needles are read **out of the hypervisor** rather than
    /// retyped here. A tag renamed on one side and not the other then fails
    /// loudly instead of quietly leaving a user with an alarming line and no
    /// page that mentions it.
    ///
    /// The tags are extracted from their `const` declarations, so a build that
    /// changes what is printed changes what this test demands.
    #[test]
    fn the_first_resume_guide_names_the_tags_the_hypervisor_prints() {
        let src = include_str!("../../hypervisor/src/hvf/mod.rs");
        let doc = flattened(include_str!("../../docs/first-resume.md"));

        // Assembled from parts: a literal needle would match this test's own
        // source if the guard were ever pointed at the file it reads.
        for name in ["WEDGE", "RECOVERED"] {
            let decl = format!("const {name}_REPORT_TAG: &str = \"");
            let Some(tag) = src
                .split_once(&decl)
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(tag, _)| tag)
            else {
                panic!(
                    "hypervisor no longer declares {name}_REPORT_TAG as a \
                     string const, so this guard can no longer read what \
                     the console will actually say"
                )
            };
            assert!(
                doc.contains(tag),
                "the hypervisor prints `{tag}` but docs/first-resume.md never \
                 mentions it, so a user who sees that line has nowhere to look"
            );
        }

        // Naming both tags is not enough: #310 is about telling them apart, so
        // the page has to say what to *do* about each. These two sentences are
        // the whole actionable content, and each appears exactly once -- unlike
        // the tags themselves, which recur throughout the section and so cannot
        // detect the loss of the sentence that matters (the #290 M5 lesson).
        for (needle, why) in [
            (
                ["The guest's complaint is behind it.", "**Nothing to do.**"].join(" "),
                "the page must say plainly that a [stall] line needs no action, \
                 or a reader who was just alarmed by a kernel stall trace is \
                 left to guess. The needle carries the preceding sentence \
                 because `Nothing to do` alone also appears in the disk-grow \
                 section, where resize2fs says it -- a needle that occurs twice \
                 cannot detect its removal from the one place that matters",
            ),
            (
                ["Report", "that one"].join(" "),
                "the page must say plainly that a [wedge] line should be \
                 reported, or the one report we actually want goes unfiled",
            ),
            (
                ["CHM_FORCE_RESUME_ADVANCE_S", "3600"].join("="),
                "the caveat has to keep the measurement that backs it, so a \
                 later tidy cannot quietly upgrade a guess about the cause \
                 into a fact",
            ),
        ] {
            assert!(doc.contains(&needle), "docs/first-resume.md: {why}");
        }
    }

    /// The success line #287's repair prints is read out of the hypervisor, not
    /// retyped in the page.
    ///
    /// The repair can decline, and it warns and continues when it does rather
    /// than refusing the resume -- so the console is the *only* place a user
    /// learns which happened, and the page is where they find out what to look
    /// for. That holds only while the page and the code agree, and they live in
    /// different crates. Restating a constant across a crate boundary is
    /// exactly how the app came to refuse kernels the engine accepts (#242).
    #[test]
    fn the_first_resume_guide_quotes_the_repair_line_the_hypervisor_prints() {
        let src = include_str!("../../hypervisor/src/hvf/rehydrate.rs");
        let doc = flattened(include_str!("../../docs/first-resume.md"));

        // Assembled from parts so this cannot match its own source, and cut at
        // the first `{` because the rest of the literal is format arguments.
        let opening = format!("\"[{}] reverted ", "icache");
        let Some(line) = src
            .split_once(&opening)
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split_once('{'))
            .map(|(head, _)| head)
        else {
            panic!(
                "the hypervisor no longer prints a `reverted` line for the \
                 #287 repair, so this guard can no longer read what a repaired \
                 capture will actually say on the console"
            )
        };
        let needle = format!("reverted {}", line.trim());
        assert!(
            doc.contains(&needle),
            "the hypervisor prints `{needle}` when it repairs the kernel's DIC \
             elision, but docs/first-resume.md does not quote it -- so a user \
             cannot tell a repaired capture from one whose repair declined, \
             and the two differ by 998 stale executions in 1000"
        );
    }

    /// Blank out whole-line comments, preserving line numbering.
    ///
    /// A guard that reads source has to survive prose *about* the thing it
    /// refuses. The allowance this one replaces is documented in `main.rs` by
    /// quoting the very form being refused, and this module's own doc comments
    /// do the same, so a scanner that cannot tell code from commentary would
    /// report the explanation as the offence.
    fn without_comment_lines(src: &str) -> String {
        src.lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Index just past a string literal opening at `at`, honouring escapes.
    fn skip_string(chars: &[char], at: usize) -> Option<usize> {
        let mut i = at + 1;
        while i < chars.len() {
            match chars[i] {
                '\\' => i += 2,
                '"' => return Some(i + 1),
                _ => i += 1,
            }
        }
        None
    }

    /// Index just past a `'x'` / `'\n'` literal at `at`, or `None` for a lifetime.
    fn skip_char_literal(chars: &[char], at: usize) -> Option<usize> {
        let mut i = at + 1;
        if chars.get(i) == Some(&'\\') {
            i += 1;
        }
        i += 1;
        (chars.get(i) == Some(&'\'')).then_some(i + 1)
    }

    /// Index of the bracket closing the one opened just before `start`.
    ///
    /// Brackets inside string and character literals do not count, or
    /// `assert!(s.contains(')'))` would appear to close early -- which would
    /// truncate the argument and hide whatever followed.
    fn matching_close(chars: &[char], start: usize) -> Option<usize> {
        let mut depth = 1usize;
        let mut i = start;
        while i < chars.len() {
            match chars[i] {
                '"' => {
                    i = skip_string(chars, i)?;
                    continue;
                }
                '\'' => {
                    if let Some(next) = skip_char_literal(chars, i) {
                        i = next;
                        continue;
                    }
                }
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// The sole argument of a macro call, or `None` when a message follows it.
    ///
    /// A trailing comma is not a message. `assert!(\n    x,\n)` is what rustfmt
    /// produces from a long single-argument call, and reading that as
    /// two arguments would let every wrapped offender through.
    fn single_argument(arg: &str) -> Option<&str> {
        let chars: Vec<char> = arg.chars().collect();
        let mut depth = 0usize;
        let mut i = 0usize;
        while i < chars.len() {
            match chars[i] {
                '"' => {
                    let Some(next) = skip_string(&chars, i) else {
                        break;
                    };
                    i = next;
                    continue;
                }
                '\'' => {
                    if let Some(next) = skip_char_literal(&chars, i) {
                        i = next;
                        continue;
                    }
                }
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    if !arg[i + 1..].trim().is_empty() {
                        return None;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        Some(arg.trim().trim_end_matches(',').trim())
    }

    /// Every `assert!`-family invocation in `src`, as `(line, argument list)`.
    ///
    /// Spans lines deliberately. A guard defeated by a line break reports
    /// safety it does not provide, and rustfmt will wrap a long assertion
    /// across three lines without being asked -- so a line-at-a-time search
    /// would go quiet the moment an offending call got long enough to matter.
    fn assert_arguments(src: &str) -> Vec<(usize, String)> {
        // Assembled, so this file is never its own offender (#241).
        let open: Vec<char> = format!("assert{}(", "!").chars().collect();
        let chars: Vec<char> = src.chars().collect();
        let mut out = Vec::new();
        let mut line = 1usize;
        for i in 0..chars.len() {
            if chars[i] == '\n' {
                line += 1;
            }
            if chars[i..].starts_with(open.as_slice())
                && let Some(end) = matching_close(&chars, i + open.len())
            {
                out.push((line, chars[i + open.len()..end].iter().collect()));
            }
        }
        out
    }

    /// The parser has to tell an offence from an explanation of one.
    ///
    /// Written against synthetic input because the tree it polices has zero
    /// offenders by the time this lands: a guard whose only evidence is "it
    /// stayed quiet" cannot distinguish working from broken.
    #[test]
    fn the_scanner_reads_assertions_the_way_clippy_does() {
        let ok = format!(".is{}()", "_ok");
        let found = |src: &str| -> Vec<usize> {
            assert_arguments(&without_comment_lines(src))
                .into_iter()
                .filter(|(_, arg)| single_argument(arg).is_some_and(|a| a.ends_with(&ok)))
                .map(|(line, _)| line)
                .collect()
        };

        let bare = format!("fn t() {{\n    assert{}(f(x){}());\n}}\n", "!", ".is_ok");
        assert_eq!(
            found(&bare),
            vec![2],
            "the plain single-line form must be caught"
        );

        let wrapped = format!(
            "fn t() {{\n    assert{}(\n        f(x)\n        {}(),\n    );\n}}\n",
            "!", ".is_ok"
        );
        assert_eq!(
            found(&wrapped),
            vec![2],
            "a wrapped assertion must still be caught"
        );

        // Everything below stays out of scope on purpose.
        let with_message = format!("assert{}(f(x){}(), \"why it should\");\n", "!", ".is_ok");
        assert!(
            found(&with_message).is_empty(),
            "a custom message says something on failure"
        );

        let err = format!("assert{}(f(x).is{}());\n", "!", "_err");
        assert!(
            found(&err).is_empty(),
            "the is_err form is deliberately still allowed"
        );

        let commented = format!("// assert{}(f(x){}());\n", "!", ".is_ok");
        assert!(
            found(&commented).is_empty(),
            "prose about the form is not the form"
        );

        let parenthesised = format!("assert{}(s.contains(')'){}());\n", "!", ".is_ok");
        assert_eq!(
            found(&parenthesised).len(),
            1,
            "a bracket inside a literal must not truncate the argument"
        );
    }

    /// No assertion may throw away the error it just caught.
    ///
    /// `assert!(x.is_ok())` prints `assertion failed: x.is_ok()` and nothing
    /// else -- the error that explains *why* is dropped on the floor at exactly
    /// the moment somebody needs it. `.unwrap()` prints it.
    ///
    /// This exists because the alternative was a comment. `main.rs` allows
    /// `clippy::assertions_on_result_states` for the whole crate under
    /// `cfg(test)`, narrowed by #365 to cover the `is_err()` form only -- and a
    /// comment saying "is_err() only" stops being true the moment somebody
    /// writes an `is_ok()`, silently, with the lint still switched off. Clippy
    /// cannot split the two: the lint has no configuration. So the half that
    /// was cleaned up is held cleaned up here instead of being asserted in
    /// prose.
    ///
    /// Scoped to what clippy itself flags, which is narrower than it looks:
    /// **an `assert!` carrying a custom message is not flagged**, because that
    /// message is a human sentence and printing it is not silence. That is the
    /// whole of the gap between #365's stated counts and the measured ones.
    #[test]
    fn no_assertion_discards_the_error_it_caught() {
        let root = repo_root();

        // Assembled from parts, so this test's own body is not an offender.
        let ok_state = format!(".is{}()", "_ok");
        let mut offenders = Vec::new();
        for file in sources() {
            let src = without_comment_lines(&fs::read_to_string(&file).expect("read source"));
            for (line, arg) in assert_arguments(&src) {
                if single_argument(&arg).is_some_and(|a| a.ends_with(&ok_state)) {
                    let shown = file
                        .strip_prefix(&root)
                        .unwrap_or(&file)
                        .display()
                        .to_string();
                    offenders.push(format!("  {shown}:{line}"));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "these assertions discard the error they caught (#365). Use \
             `.unwrap()`, which prints it, or add a message saying what was \
             expected:\n{}",
            offenders.join("\n")
        );

        // `hypervisor` needs no scanner: #365 deleted its allowance outright,
        // because converting its two `is_err()` sites left nothing needing one.
        // Clippy polices it directly from then on, and does it better than this
        // test could -- a scanner reads every `cfg`, clippy reads the ones that
        // are actually built. That division only holds while the allowance
        // stays gone, so this is the half that has to be asserted here.
        let lib = fs::read_to_string(root.join("hypervisor").join("src").join("lib.rs"))
            .expect("read hypervisor/src/lib.rs");
        let lint = format!("assertions_on{}", "_result_states");
        assert!(
            !flattened(&without_comment_lines(&lib)).contains(&lint),
            "hypervisor/src/lib.rs allows `{lint}` again, so clippy has stopped \
             catching there what this test only catches in chm (#365)"
        );
    }

    /// Every page under `docs/` is reachable from `docs/README.md`.
    ///
    /// #368: the browser sandbox shipped as V11 — the newest headline
    /// capability — with no page and no index entry, so `grep -ci browser
    /// docs/README.md` returned 0 and a reader had no route to
    /// `chm/src/oci/browser.rs` or the acceptance script at all. Writing the
    /// page fixes that once; this guard is what stops the *next* page being
    /// unreachable.
    ///
    /// **The honest limit, stated up front:** this pins structure, not
    /// currency. It can prove a page is indexed and that its links resolve. It
    /// cannot prove the page is true, or current, and claiming otherwise would
    /// repeat #368's own failure one level up — a document asserting a state it
    /// has not rechecked.
    #[test]
    fn every_doc_page_is_reachable_from_the_index() {
        let docs = repo_root().join("docs");
        let index = fs::read_to_string(docs.join("README.md")).expect("read docs/README.md");

        let mut pages: Vec<String> = fs::read_dir(&docs)
            .expect("read docs/")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "md"))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .filter(|n| n != "README.md" && n != "AGENTS.md")
            .collect();
        pages.sort();
        assert!(
            !pages.is_empty(),
            "found no docs pages to check; the walk is broken"
        );

        let unindexed: Vec<&String> = pages.iter().filter(|n| !index.contains(*n)).collect();
        assert!(
            unindexed.is_empty(),
            "docs/README.md does not link {unindexed:?}, so a reader browsing \
             the index has no route to {} — the exact shape of #368, where the \
             newest shipped capability was undiscoverable",
            unindexed.len()
        );
    }

    /// Every relative link in `docs/` resolves to a file that exists.
    ///
    /// A dead link is the same defect as a missing index entry wearing a
    /// disguise: the reader is told a route exists and it does not. This also
    /// keeps the index guard above honest, since that one is satisfied by the
    /// *filename appearing* in `README.md` and would otherwise accept a link
    /// pointing at nothing.
    #[test]
    fn every_doc_link_points_at_a_file_that_exists() {
        let docs = repo_root().join("docs");
        let mut broken: Vec<String> = Vec::new();
        let mut checked = 0usize;

        for entry in fs::read_dir(&docs).expect("read docs/").flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "md") {
                continue;
            }
            let page = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&path).expect("read a docs page");

            for target in markdown_link_targets(&text) {
                // Anchors, absolute URLs and mail links are not ours to resolve.
                if target.starts_with('#')
                    || target.contains("://")
                    || target.starts_with("mailto:")
                {
                    continue;
                }
                let file = target.split('#').next().unwrap_or(&target);
                if file.is_empty() {
                    continue;
                }
                if !docs.join(file).exists() {
                    broken.push(format!("{page} -> {file}"));
                }
                checked += 1;
            }
        }

        // Without this the test passes when the parser finds nothing, which is
        // the failure mode it is least likely to notice: an empty result set
        // reads exactly like a clean one. The floor is deliberately far below
        // the real count so it tracks a broken parser, not the doc set's size.
        assert!(
            checked > 20,
            "only {checked} relative doc links were checked, which is too few to \
             be real — the link parser has stopped finding links and this guard \
             is passing on an empty set rather than on a clean one"
        );

        broken.sort();
        assert!(
            broken.is_empty(),
            "these docs links point at files that do not exist: {broken:?}"
        );
    }

    /// The targets of every inline markdown link `[text](target)` in `text`.
    ///
    /// Deliberately does not try to parse markdown. It finds `](` and reads to
    /// the matching `)`, which is enough for the link forms these pages use and
    /// fails toward a loud false positive rather than a quiet miss.
    fn markdown_link_targets(text: &str) -> Vec<String> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] == b']' && bytes[i + 1] == b'(' {
                let start = i + 2;
                if let Some(len) = bytes[start..].iter().position(|&b| b == b')') {
                    out.push(text[start..start + len].trim().to_string());
                    i = start + len;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// The base64 alphabet may be written down exactly once.
    ///
    /// #375: this crate carried two encoders — `credproxy::base64::encode` and a
    /// private `base64_encode` in `credproxy/cli.rs` — that were the same
    /// algorithm line for line. They agreed. Nothing made them keep agreeing,
    /// and nothing would have reported it if they stopped: the tests for each
    /// copy say nothing about the other.
    ///
    /// The asymmetry is what makes this a lint rather than tidiness. One copy
    /// builds HTTP Basic headers on the credential-injection path, so it
    /// encodes secrets; the other builds the console transfer that installs the
    /// proxy CA into a guest. A divergence in either is security-relevant.
    ///
    /// Guarding the *alphabet* rather than the function name is deliberate: a
    /// third encoder will not be called `base64_encode`, but it cannot avoid
    /// writing the alphabet down.
    #[test]
    fn the_base64_alphabet_is_written_down_exactly_once() {
        // Assembled at runtime so this guard is not satisfied by its own source
        // (#241): a literal here would itself be a second occurrence.
        let upper: String = (b'A'..=b'Z').map(char::from).collect();
        let lower: String = (b'a'..=b'z').map(char::from).collect();
        let digits: String = (b'0'..=b'9').map(char::from).collect();
        let alphabet = format!("{upper}{lower}{digits}+/");

        let carriers: Vec<String> = sources()
            .into_iter()
            .filter(|p| {
                fs::read_to_string(p)
                    .expect("read source")
                    .contains(&alphabet)
            })
            .map(|p| p.display().to_string())
            .collect();

        assert_eq!(
            carriers.len(),
            1,
            "the base64 alphabet must appear in exactly one file, found it in {carriers:?}; \
             call credproxy::base64::encode instead of writing another encoder"
        );
        assert!(
            carriers[0].ends_with("credproxy/base64.rs"),
            "the one base64 alphabet should live in credproxy/base64.rs, found it in {}",
            carriers[0]
        );
    }

    /// `state_cdn` keeps its own decoder on purpose, and that is load-bearing.
    ///
    /// `cli.rs`'s transfer test encodes with `credproxy::base64::encode` and
    /// decodes with `state_cdn::base64_decode`, because an encoder checked
    /// against its own inverse proves nothing — the two would have to agree even
    /// if both were wrong. The guest then uses a third implementation
    /// (`base64 -d`), which is the one that actually has to match.
    ///
    /// This guard exists because consolidating those two decoders makes the
    /// suite **greener and weaker with no failure**: the reassembly test would
    /// still pass, having quietly become a check of one module against itself.
    /// A reviewer tidying `state_cdn` would see a duplicate and be right about
    /// the code and wrong about the consequence, so the reason has to be
    /// enforced rather than written in a comment in a different file.
    #[test]
    fn the_transfer_test_decodes_with_an_independent_implementation() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let cdn = fs::read_to_string(src.join("state_cdn.rs")).expect("read state_cdn.rs");
        let cli = fs::read_to_string(src.join("credproxy/cli.rs")).expect("read cli.rs");

        // Assembled from parts so neither needle matches this guard's own text.
        let owns_decoder = format!("fn {}_decode(", "base64");
        assert!(
            cdn.contains(&owns_decoder),
            "state_cdn must keep its own base64 decoder: it is the independent \
             oracle the transfer reassembly test checks the encoder against"
        );

        let cross_module = format!("crate::state_cdn::{}_decode(", "base64");
        assert!(
            cli.contains(&cross_module),
            "the transfer reassembly test must decode with state_cdn's decoder, \
             not with credproxy::base64::decode, or it checks the encoder \
             against its own inverse and proves nothing"
        );

        // Surviving by name is not enough. The tidy-up most likely to be
        // attempted is to keep the signature and have the body delegate, which
        // leaves both assertions above green while deleting the very thing they
        // are protecting.
        let start = cdn.find(&owns_decoder).expect("decoder located above");
        let body = &cdn[start..];
        let end = body.find("\n}\n").expect("decoder has a closing brace");
        assert!(
            !body[..end].contains("credproxy"),
            "state_cdn's base64 decoder must not delegate to credproxy: a \
             decoder that forwards is not an independent oracle, it is the \
             same implementation reached by a second name"
        );
    }

    /// `docs/credential-proxy.md` teaches the commands that exist, not
    /// workarounds for bugs that are fixed.
    ///
    /// The page's "doing it from the CLI alone" section spent three releases
    /// telling a reader to hand-roll a base64 chunk loop because `chm cp` did
    /// not exist (#316), and to distrust `chm proxy check` because it ignored
    /// `--workspace` (#317). Both shipped; the advice did not move (#377).
    ///
    /// The absence half is the load-bearing half, and for the same reason
    /// `the_first_resume_guide_says_what_was_measured` gives above: a
    /// superseded procedure reads perfectly well on its own, so nothing about
    /// the paragraph itself invites a reader to delete it. The way it comes
    /// back is by someone restoring a section that looks fine.
    ///
    /// Telling a user to distrust `chm proxy check` is the sharpest of the
    /// three: it is the command reached for as *evidence*, so the advice does
    /// not merely waste time, it withdraws the tool's own answer.
    ///
    /// `flattened` is load-bearing, not tidiness: prose wraps, so a reinstated
    /// claim arrives split across a newline and sails past a raw `contains`.
    /// Mutation-proved by re-adding the distrust sentence with a line break in
    /// the middle of the needle.
    #[test]
    fn the_credential_proxy_guide_names_the_commands_that_exist() {
        let doc = flattened(include_str!("../../docs/credential-proxy.md"));

        // The sequence a reader will paste, in the form it was measured.
        for (needle, why) in [
            (
                "chm cp ./ca-install.sh /tmp/ca.sh",
                "the transfer step must be `chm cp` (#316), which verifies by \
                 SHA-256 on both sides, not a hand-rolled chunk loop",
            ),
            (
                "chm proxy check --workspace ./ws",
                "the page must show how to confirm injection, now that \
                 `--workspace` is honoured (#317)",
            ),
        ] {
            assert!(
                doc.contains(needle),
                "docs/credential-proxy.md no longer shows `{needle}`, so it has \
                 stopped teaching the working path: {why}"
            );
        }

        // The superseded advice, which must not return. Each needle is unique
        // to the workaround itself, never to the note explaining that the bug
        // behind it was fixed -- a needle matching both cannot detect the one
        // that matters (the #290 doc-guard lesson).
        for (needle, why) in [
            (
                "fold -w 1200",
                "the manual base64 chunking recipe is superseded by `chm cp`",
            ),
            (
                "/tmp/ca.b64",
                "the chunk-append scratch file belongs to the recipe `chm cp` \
                 replaced",
            ),
            (
                "until it is fixed, do not trust it",
                "`chm proxy check --workspace` works (#317); telling a reader \
                 to distrust it withdraws the evidence the page exists to give",
            ),
        ] {
            assert!(
                !doc.to_lowercase().contains(needle),
                "docs/credential-proxy.md has reinstated superseded advice \
                 (`{needle}`): {why}"
            );
        }
    }

    /// `docs/release-facts.md` records the things a release needs that do not
    /// live in this repository -- the signing identity, when its certificate
    /// stops working, and how notarization is authenticated. None of that can
    /// be checked by building the tree, so the page is the only record, and a
    /// page that has drifted from the script is worse than no page: it is
    /// instructions that fail after the four-minute Apple round trip rather
    /// than before it.
    ///
    /// Two different drifts are guarded, because neither implies the other.
    ///
    /// The first is the script renaming a knob the page tells a reader to set.
    /// That is why the environment variables and the default profile name are
    /// read out of `release-macos.sh` rather than restated here -- the same
    /// coupling `grow_sequence()` gives `docs/first-resume.md` (#284).
    ///
    /// The second is the page losing a fact that cost a measurement to learn.
    /// The expiry date is the whole reason #391 was filed: a certificate that
    /// nothing watches is a dateable outage, and this paragraph is currently
    /// the only thing that watches it. The `security find-generic-password`
    /// trap is the other -- that tool cannot see the data protection keychain,
    /// so it reports a working credential as missing, and a reader who has
    /// lost that sentence will conclude the release is unrepeatable when it is
    /// not.
    #[test]
    fn the_release_facts_page_matches_the_script_it_documents() {
        let doc = flattened(include_str!("../../docs/release-facts.md"));
        let script = flattened(include_str!("../../scripts/release-macos.sh"));

        for var in ["GIMBAL_SIGN_IDENTITY", "GIMBAL_NOTARY_PROFILE"] {
            assert!(
                script.contains(var),
                "scripts/release-macos.sh no longer reads `{var}`, so \
                 docs/release-facts.md is telling a releaser to set a variable \
                 that does nothing"
            );
            assert!(
                doc.contains(var),
                "docs/release-facts.md no longer names `{var}`, which the \
                 release script still requires -- the page has stopped \
                 describing how to drive it"
            );
        }

        let default_profile = "gimbal-notary";
        assert!(
            script.contains(&format!("GIMBAL_NOTARY_PROFILE:-{default_profile}")),
            "the release script's default notary profile is no longer \
             `{default_profile}`, so every `notarytool` command in \
             docs/release-facts.md now names the wrong profile"
        );
        assert!(
            doc.contains(default_profile),
            "docs/release-facts.md no longer names the `{default_profile}` \
             profile, so it cannot tell anyone how to check or recreate the \
             notarization credential"
        );

        for (needle, why) in [
            (
                "2027-02-01",
                "the certificate expiry is the dateable risk #391 was filed \
                 for, and this page is the only place it is recorded",
            ),
            (
                "89N7ZG42ZM",
                "the team ID is what identifies the account a re-run needs \
                 access to",
            ),
            (
                "security find-generic-password",
                "the page has lost the measured trap that this tool cannot \
                 see the data protection keychain, so the next reader will \
                 read a working credential as a missing one",
            ),
        ] {
            assert!(
                doc.contains(needle),
                "docs/release-facts.md no longer carries `{needle}`: {why}"
            );
        }

        // The page tells a releaser how much lead time the warning gives them,
        // and the script is where that number really lives. Read it out rather
        // than restating it, so the two cannot drift into disagreeing about a
        // renewal deadline.
        let warning_days: String = script
            .split_once("signing_expiry_warning_days=")
            .expect(
                "scripts/release-macos.sh no longer defines \
                 `signing_expiry_warning_days`, so the certificate-expiry \
                 preflight that docs/release-facts.md describes has gone",
            )
            .1
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        assert!(
            !warning_days.is_empty(),
            "`signing_expiry_warning_days` in scripts/release-macos.sh is no \
             longer a plain number of days, so docs/release-facts.md cannot be \
             held to it"
        );
        assert!(
            doc.contains(&format!("**{warning_days}** days")),
            "docs/release-facts.md does not say the release preflight warns \
             `**{warning_days}** days` ahead, which is the window the script \
             actually applies -- a reader would plan the renewal against the \
             wrong lead time"
        );
    }

    /// #376: two statements welded onto one line by a bad edit.
    ///
    /// An `edit` whose `old_str` ends in a newline and whose `new_str` does not
    /// joins the two lines around it. The result compiles, `cargo build` is
    /// silent, and clippy says nothing -- so it survives every gate this repo
    /// runs and is only ever found by a human reading the file. Five had
    /// accumulated across three crates before anyone noticed, one of them
    /// welding a doc comment onto the item below it so the doc described the
    /// wrong thing.
    ///
    /// rustfmt would also split these, but the repo has no fmt gate and a
    /// measured whole-tree drift of ~54 files, so "run rustfmt" is not a
    /// control that exists here. This is the narrow, zero-false-positive
    /// subset: a statement keyword four or more spaces after an opening brace
    /// is never deliberate formatting.
    #[test]
    fn no_source_line_welds_a_statement_onto_an_opening_brace() {
        let root = repo_root();
        let mut welded = Vec::new();
        for dir in ["chm/src", "hypervisor/src", "arch/src"] {
            let dir = root.join(dir);
            if !dir.is_dir() {
                continue;
            }
            for path in sources_under(&dir) {
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                for (n, line) in text.lines().enumerate() {
                    if welds_a_statement(line) {
                        welded.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            welded.is_empty(),
            "{} line(s) weld a statement onto an opening brace -- almost certainly a bad \
             edit rather than intent, and it hides what the line actually does:\n{}",
            welded.len(),
            welded.join("\n")
        );
    }

    /// `{` then four or more spaces then a statement keyword.
    ///
    /// Split out so the predicate is testable: the guard above can only ever
    /// report that today's tree is clean, which is exactly the shape that
    /// cannot tell a working check from a broken one.
    fn welds_a_statement(line: &str) -> bool {
        // A line comment ends the code, so anything after it is prose.
        let code = line.split_once("//").map_or(line, |(before, _)| before);
        let bytes = code.as_bytes();
        let mut in_string = false;
        let mut escaped = false;
        for (i, &b) in bytes.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' if in_string => escaped = true,
                b'"' => in_string = !in_string,
                // A `{` inside a string literal is a format placeholder, not an
                // opening brace -- the commonest false positive by far, and the
                // reason this walks the line instead of splitting on the first
                // brace. Splitting naively also *missed* the real weld that
                // motivated this guard, because it carried `Some("audit")`
                // ahead of its brace.
                b'{' if !in_string => {
                    let rest = &code[i + 1..];
                    let trimmed = rest.trim_start();
                    let gap = rest.len() - trimmed.len();
                    if gap >= 4
                        && rest.starts_with(' ')
                        && ["let ", "if ", "return ", "for ", "match ", "while "]
                            .iter()
                            .any(|kw| trimmed.starts_with(kw))
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    #[test]
    fn the_weld_predicate_sees_a_weld_and_ignores_ordinary_code() {
        assert!(welds_a_statement(
            "    pub fn new(n: u32) -> Self {        let x = 1;"
        ));
        assert!(welds_a_statement(
            "    if a == Some(\"audit\") {        let tail = rest"
        ));
        // Ordinary formatting: the statement is on its own line.
        assert!(!welds_a_statement("    fn new() -> Self {"));
        assert!(!welds_a_statement("        let x = 1;"));
        // A brace inside a string is not an opening brace.
        assert!(!welds_a_statement(r#"    println!("{}        let x", v);"#));
        // Two spaces is alignment, not a weld.
        assert!(!welds_a_statement("    fn f() {  let x = 1;"));
    }

    /// `docs/networking.md` teaches the live-amendment surface that exists.
    ///
    /// Three claims on that page are load-bearing and each fails in a different
    /// direction if it drifts from the code (#156):
    ///
    /// - The **command form** is quoted from `EGRESS_USAGE`, the same constant
    ///   every refusal quotes. A doc that teaches a form the parser rejects
    ///   sends a user to the one place that cannot help them.
    /// - The **`+live` label** is the reason an amended policy cannot be
    ///   mistaken for a cloud-issued digest. If `amend()` stopped moving the
    ///   label, the page would still promise a marker that no longer appears,
    ///   and a reader comparing an audit record against a bound digest would
    ///   conclude they matched.
    /// - **Established flows are retained**, which is the sentence that stops a
    ///   user believing a `deny` severed the transfer they are watching.
    ///
    /// The needles are read out of the source rather than retyped, so a rename
    /// fails here instead of leaving the page quietly wrong. `flattened` is
    /// load-bearing for the prose ones: a wrapped line defeats a raw `contains`
    /// (#288's guard was caught by exactly that).
    #[test]
    fn the_networking_guide_teaches_the_amendment_surface_that_exists() {
        let doc = flattened(include_str!("../../docs/networking.md"));

        assert!(
            doc.contains(crate::serve::EGRESS_USAGE),
            "docs/networking.md must quote the form `chm ctl egress` actually \
             accepts ({}), or it teaches a command the parser refuses",
            crate::serve::EGRESS_USAGE
        );

        for (needle, why) in [
            (
                "labelled `<base>+liven`",
                "the page promises an amended policy is labelled `<base>+liveN`, \
                 which is what stops it being read as a cloud-issued digest. The \
                 needle is the whole claim, not the bare `+live`: that substring \
                 also appears in the worked example below it, so a needle short \
                 enough to match both could not see the claim being deleted",
            ),
            (
                "established flows continue",
                "the page must say an amendment governs admission only, or a \
                 user reads a still-running transfer as a failed deny",
            ),
        ] {
            assert!(
                doc.to_lowercase().contains(needle),
                "docs/networking.md no longer says `{needle}`: {why}"
            );
        }
    }
}
