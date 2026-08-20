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

    /// Every `.rs` file under `chm/src`.
    fn sources() -> Vec<PathBuf> {
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
        walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
        out.sort();
        assert!(!out.is_empty(), "found no sources to scan; the walk is broken");
        out
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
}
