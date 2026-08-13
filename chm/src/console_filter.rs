// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Console output filtering for the interactive serial stream.
//!
//! A resumed guest's PL061 GPIO driver re-requests its SPI trigger mode at
//! runtime (notably during the udev coldplug at login). Apple's *managed* GIC
//! owns the distributor MMIO and does not honor that runtime reconfiguration, so
//! the guest's GICv3 driver logs `genirq: Setting trigger mode N for irq M
//! failed (gic_set_type+...)` — a bounded but noisy burst that can drown an
//! interactive login. This is a documented platform limitation (the host cannot
//! satisfy the read-back), so we drop just that one well-known cosmetic line
//! from the *rendered* console.
//!
//! The filter is deliberately conservative: it only ever holds back bytes that
//! are still a viable prefix of a kernel printk timestamp line (`[   12.345] …`).
//! Interactive prompts, echoed keystrokes, and ordinary command output never
//! match that prefix and pass through immediately, so latency and correctness of
//! the interactive session are preserved. Set `CHM_RAW_CONSOLE=1` to disable it
//! entirely and see the raw guest console.

use std::env;
use std::mem;

use hypervisor::hvf::request_wedge_report;

/// Filters a byte stream of guest serial output, dropping the single known
/// cosmetic genirq noise line while passing everything else through unchanged.
pub(crate) struct ConsoleFilter {
    enabled: bool,
    /// Bytes of an in-progress line that is still a viable kernel-printk line
    /// (begins `[` and so far matches the `[ <secs>.<frac>] ` timestamp shape).
    held: Vec<u8>,
    /// Watches the same stream for the guest kernel announcing that its own
    /// timer tick has stopped.
    stalls: StallWatch,
}

impl ConsoleFilter {
    pub(crate) fn new() -> Self {
        Self {
            enabled: env::var_os("CHM_RAW_CONSOLE").is_none(),
            held: Vec::new(),
            stalls: StallWatch::default(),
        }
    }

    /// Feed a chunk of guest output; returns the bytes that should be written to
    /// the host console. Bytes that belong to a not-yet-complete kernel line are
    /// withheld until the line completes (then emitted or dropped).
    pub(crate) fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        // Before any filtering decision, and regardless of whether filtering is
        // enabled at all: a guest that says its own tick has stopped is the one
        // observer that can see a stall our counter is blind to.
        self.stalls.scan(input);
        if !self.enabled {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity(input.len() + self.held.len());
        for &b in input {
            if self.held.is_empty() {
                if b == b'[' {
                    self.held.push(b);
                } else {
                    out.push(b);
                }
                continue;
            }

            self.held.push(b);
            if b == b'\n' {
                // A complete line: drop it only if it is the known noise.
                if !is_genirq_noise(&self.held) {
                    out.append(&mut self.held);
                }
                self.held.clear();
            } else if !viable_kernel_prefix(&self.held) {
                // No longer a possible kernel timestamp line (e.g. the user typed
                // `[` then a letter): release what we held and stop buffering.
                out.append(&mut self.held);
            }
        }
        out
    }

    /// Release any held partial line. Call when the stream ends so a withheld
    /// (incomplete) kernel line is not lost.
    pub(crate) fn flush(&mut self) -> Vec<u8> {
        mem::take(&mut self.held)
    }
}

/// True while `buf` is still a viable prefix of a kernel printk timestamp line
/// of the form `[ *\d+\.\d+\] ` followed by the message body.
fn viable_kernel_prefix(buf: &[u8]) -> bool {
    // State machine over the timestamp shape; once we reach the body any byte is
    // fine. Returns false the moment a byte cannot continue the pattern.
    #[derive(Clone, Copy)]
    enum S {
        Open,    // expect '['
        Lead,    // spaces then first integer digit
        IntPart, // integer digits, then '.'
        FracOne, // first fractional digit
        Frac,    // fractional digits, then ']'
        Space,   // expect ' '
        Body,    // anything
    }
    let mut s = S::Open;
    for &b in buf {
        s = match s {
            S::Open if b == b'[' => S::Lead,
            S::Lead if b == b' ' => S::Lead,
            S::Lead if b.is_ascii_digit() => S::IntPart,
            S::IntPart if b.is_ascii_digit() => S::IntPart,
            S::IntPart if b == b'.' => S::FracOne,
            S::FracOne if b.is_ascii_digit() => S::Frac,
            S::Frac if b.is_ascii_digit() => S::Frac,
            S::Frac if b == b']' => S::Space,
            S::Space if b == b' ' => S::Body,
            S::Body => S::Body,
            _ => return false,
        };
    }
    true
}

/// The one cosmetic line we drop: the PL061 GPIO SPI trigger reconfiguration the
/// managed GIC rejects. Matched by its stable substrings, not the varying
/// timestamp / irq number.
fn is_genirq_noise(line: &[u8]) -> bool {
    contains(line, b"genirq: Setting trigger mode") && contains(line, b"gic_set_type")
}

/// The phrases a Linux guest prints when it has decided, itself, that a CPU's
/// timer tick has stopped advancing.
///
/// Both are emitted once per stall episode rather than once per line of the
/// block, which is why they are matched instead of the more common `rcu:` prefix
/// — the block carries half a dozen `rcu:` lines and only these two are the
/// kernel's actual verdict.
const STALL_PHRASES: [&[u8]; 2] = [
    b"rcu_preempt kthread starved",
    b"detected stalls on CPUs/tasks",
];

/// Scans the guest console for those phrases and asks every vCPU to report its
/// interrupt-delivery state when one appears.
///
/// This is the trigger #257 never had. The bug has been seen twice and
/// reproduced never, and on both occasions the guest kernel *did* announce the
/// stall — but nothing was listening, so the console recorded a symptom with
/// none of the state that would have said whose fault it was.
///
/// It carries a tail of the previous chunk so a phrase split across two reads is
/// still matched: guest output arrives in whatever sizes the PL011 FIFO drains
/// in, and a boundary landing mid-phrase would otherwise silently lose the one
/// event this exists to catch.
#[derive(Default)]
struct StallWatch {
    tail: Vec<u8>,
    fired: u32,
}

/// How many times the console trigger will ask for a report. The guest reprints
/// its stall every 60 s for as long as it lasts, and the answer does not change.
const STALL_REQUEST_LIMIT: u32 = 4;

impl StallWatch {
    fn scan(&mut self, input: &[u8]) {
        if self.fired >= STALL_REQUEST_LIMIT {
            return;
        }
        let longest = STALL_PHRASES.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut window = mem::take(&mut self.tail);
        window.extend_from_slice(input);
        let hit = STALL_PHRASES.iter().any(|p| contains(&window, p));
        // Keep just enough of the tail that a phrase straddling the next read is
        // still found, and no more: this sits on the console path.
        let keep = window.len().saturating_sub(longest.saturating_sub(1));
        self.tail = window[keep..].to_vec();
        if hit {
            self.fired += 1;
            request_wedge_report();
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(filter: &mut ConsoleFilter, chunks: &[&str]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(filter.feed(c.as_bytes()));
        }
        out.extend(filter.flush());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn drops_the_genirq_noise_line() {
        let mut f = ConsoleFilter::new();
        let line = "[  183.434539] genirq: Setting trigger mode 1 for irq 12 failed \
                    (gic_set_type+0x0/0x200)\n";
        let out = run(&mut f, &[line]);
        assert_eq!(out, "");
    }

    #[test]
    fn keeps_ordinary_kernel_lines() {
        let mut f = ConsoleFilter::new();
        let line = "[    1.234567] EXT4-fs (vda1): mounted filesystem\n";
        assert_eq!(run(&mut f, &[line]), line);
    }

    #[test]
    fn passes_an_interactive_prompt_without_newline_immediately() {
        let mut f = ConsoleFilter::new();
        // A shell prompt has no trailing newline; it must not be withheld.
        let out = f.feed(b"ubuntu@ch-snap:~$ ");
        assert_eq!(out, b"ubuntu@ch-snap:~$ ");
    }

    #[test]
    fn echoes_a_typed_open_bracket_without_waiting_for_newline() {
        let mut f = ConsoleFilter::new();
        // User types '[' then 'l' (e.g. `ls`): the '[' is held one byte, then
        // released as soon as 'l' proves it is not a kernel timestamp line.
        assert_eq!(f.feed(b"["), b"");
        assert_eq!(f.feed(b"l"), b"[l");
    }

    #[test]
    fn drops_noise_split_across_feeds() {
        let mut f = ConsoleFilter::new();
        let out = run(
            &mut f,
            &[
                "[  9.9] genirq: Setting trigger mode 1 ",
                "for irq 12 failed (gic_set_type+0x0/0x200)\n",
            ],
        );
        assert_eq!(out, "");
    }

    #[test]
    fn raw_mode_passes_everything() {
        // Construct a filter with filtering disabled (as CHM_RAW_CONSOLE=1 does).
        let mut f = ConsoleFilter {
            enabled: false,
            held: Vec::new(),
            stalls: StallWatch::default(),
        };
        let noise = "[  1.0] genirq: Setting trigger mode 1 for irq 12 failed (gic_set_type)\n";
        assert_eq!(run(&mut f, &[noise]), noise);
    }

    #[test]
    fn interleaved_prompt_and_noise() {
        let mut f = ConsoleFilter::new();
        let out = run(
            &mut f,
            &[
                "[  1.0] genirq: Setting trigger mode 1 for irq 12 failed (gic_set_type)\n",
                "ubuntu@ch-snap:~$ ",
            ],
        );
        assert_eq!(out, "ubuntu@ch-snap:~$ ");
    }

    /// The kernel's own stall verdict must be recognised, and ordinary console
    /// traffic must not be.
    ///
    /// This is the trigger #257 never had. Both times the wedge occurred the
    /// guest printed exactly these phrases and nothing was listening, so the
    /// only record was a symptom with none of the state that would have said
    /// whose fault it was.
    #[test]
    fn the_kernels_own_stall_verdict_is_recognised_and_normal_output_is_not() {
        let mut w = StallWatch::default();
        w.scan(b"[ 5879.1] rcu: rcu_preempt kthread starved for 60011 jiffies! ->cpu=1\n");
        assert_eq!(
            w.fired, 1,
            "the kernel's starvation verdict must trigger a report"
        );

        let mut w = StallWatch::default();
        w.scan(b"[ 5879.1] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:\n");
        assert_eq!(w.fired, 1, "the stall announcement must trigger a report");

        // Everything a healthy guest prints, including RCU lines that are not
        // the verdict, must leave it alone.
        let mut w = StallWatch::default();
        w.scan(b"ubuntu@ch-snap:~$ dmesg | grep rcu\n");
        w.scan(b"[    0.0] rcu: Preemptible hierarchical RCU implementation.\n");
        w.scan(b"[    9.5] random: crng init done\n");
        assert_eq!(
            w.fired, 0,
            "ordinary console output must not trigger a report"
        );
    }

    /// Guest output arrives in whatever sizes the PL011 FIFO drains in, so the
    /// one line this exists to catch can land split across two reads. Matching
    /// only within a single chunk would silently lose it — and the loss would be
    /// invisible, because the symptom it is meant to catch is itself silence.
    #[test]
    fn a_stall_verdict_split_across_two_reads_is_still_matched() {
        let mut w = StallWatch::default();
        w.scan(b"[ 5879.1] rcu: rcu_preempt kthread st");
        assert_eq!(w.fired, 0, "not yet a complete phrase");
        w.scan(b"arved for 60011 jiffies! ->cpu=1\n");
        assert_eq!(w.fired, 1, "the phrase completes across the boundary");
    }

    /// A guest reprints its stall every 60 s for as long as it lasts, and the
    /// answer does not change. Without a cap a wedge that is never cleared would
    /// keep asking for reports for the rest of the run.
    #[test]
    fn repeated_stall_verdicts_stop_asking_for_reports() {
        let mut w = StallWatch::default();
        for _ in 0..50 {
            w.scan(b"[ 5879.1] rcu: rcu_preempt kthread starved for 60011 jiffies!\n");
        }
        assert_eq!(w.fired, STALL_REQUEST_LIMIT, "requests must be bounded");
    }

    /// The watcher must keep working when console filtering is switched off:
    /// `CHM_RAW_CONSOLE` exists to see the unfiltered guest console, which is
    /// exactly what someone debugging a wedge would set.
    #[test]
    fn raw_console_mode_still_watches_for_stalls() {
        let mut f = ConsoleFilter {
            enabled: false,
            held: Vec::new(),
            stalls: StallWatch::default(),
        };
        let line = "[ 5879.1] rcu: rcu_preempt kthread starved for 60011 jiffies!\n";
        assert_eq!(
            run(&mut f, &[line]),
            line,
            "raw mode still passes bytes through"
        );
        assert_eq!(f.stalls.fired, 1, "and still notices the stall");
    }
}
