// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

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

/// Filters a byte stream of guest serial output, dropping the single known
/// cosmetic genirq noise line while passing everything else through unchanged.
pub(crate) struct ConsoleFilter {
    enabled: bool,
    /// Bytes of an in-progress line that is still a viable kernel-printk line
    /// (begins `[` and so far matches the `[ <secs>.<frac>] ` timestamp shape).
    held: Vec<u8>,
}

impl ConsoleFilter {
    pub(crate) fn new() -> Self {
        Self {
            enabled: env::var_os("CHM_RAW_CONSOLE").is_none(),
            held: Vec::new(),
        }
    }

    /// Feed a chunk of guest output; returns the bytes that should be written to
    /// the host console. Bytes that belong to a not-yet-complete kernel line are
    /// withheld until the line completes (then emitted or dropped).
    pub(crate) fn feed(&mut self, input: &[u8]) -> Vec<u8> {
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
        let out = run(
            &mut f,
            &["[  183.434539] genirq: Setting trigger mode 1 for irq 12 failed (gic_set_type+0x0/0x200)\n"],
        );
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
}
