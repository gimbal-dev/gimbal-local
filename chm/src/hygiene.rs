// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Properties of the test suite itself, checked by the test suite.
//!
//! Everything here guards against a failure mode that produces a *flaky* test
//! rather than a wrong program: a test that fails once in hundreds of runs, for
//! reasons invisible in its own source, and that cannot be reproduced afterwards
//! because the conditions were an accident of thread scheduling.
//!
//! That class is worth its own module because it is the class we have actually
//! been bitten by twice, and because the cost of the bite is paid in hours of
//! someone else's time rather than in a user-visible defect.

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
}
