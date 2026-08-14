// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `chm image build --browser` — a guest that is a browser and nothing else
//! (V11.2, #331).
//!
//! # What this builds
//!
//! An arm64 rootfs holding `chromium-headless-shell`, the shared libraries it
//! links against, and no package manager. The guest boots straight into the
//! browser, which listens for CDP on port 9222; `chm create --expose 9222`
//! (#330) is what makes that reachable from the host, and Playwright's
//! `connectOverCDP` is the contract on the other end (#332).
//!
//! The security argument for exposing a raw CDP port at all is that the blast
//! radius is a VM whose entire contents are a browser. Raw CDP can read
//! `file://` and write downloads, so that argument is doing real work — which
//! is why [`REMOVED`] exists, and why nothing here adds a shell server, an
//! exec endpoint, or an sshd. `kernel/kernel-images` ships `/process/exec` and
//! `/process/spawn` in its equivalent image; that is precisely the part not
//! reused.
//!
//! # Why this browser
//!
//! Measured for #329, arm64, from the Playwright CDN:
//!
//! | build | download | Playwright native deps |
//! | --- | --- | --- |
//! | chromium (full) | 165.1 MB | 22 |
//! | **chromium-headless-shell** | **103.0 MB** | **22** |
//! | firefox | 85.8 MB | 27 |
//! | webkit | 84.6 MB | 57 |
//!
//! WebKit has the smallest download and by far the largest dependency closure,
//! so choosing on download size picks the wrong engine — and neither Firefox
//! nor WebKit speaks CDP. Google's chrome-for-testing publishes no linux-arm64
//! build at all, which is the single reason `kernel-images` cannot be reused
//! as-is on Apple Silicon.
//!
//! # Why Ubuntu noble, when #329 said "Ubuntu is out"
//!
//! #329 ruled Ubuntu out because its `chromium-browser` package is
//! `1snap1-0ubuntu2`, a snap shim that cannot work in a container. That
//! judgement stands and this image never installs it: the browser comes from
//! the Playwright CDN, and Ubuntu supplies only libraries.
//!
//! What decided the base is the *compression of the `.deb` payloads*, measured
//! 2026-08-14 with `ar t`:
//!
//! - Debian bookworm: `data.tar.xz` — and chm vendors no xz decoder.
//! - Ubuntu noble: `data.tar.zst`, 49 of 49 — and `zstd` is already a chm
//!   dependency, used for zstd image layers since #206.
//!
//! Basing on bookworm would mean adding an xz implementation to the tree to
//! read library archives, which is a new dependency and a new parser for no
//! gain. Noble reaches the same libraries through the decoder
//! [`super::image::read_blob`] already has.
//!
//! # Untrusted input, and why it goes the long way round
//!
//! The `.deb` payloads and the browser zip are attacker-influenced content in
//! exactly the sense a registry layer is. Rather than extract them by a second
//! path, each artefact is turned into a [`targz::Layer`] and handed to
//! [`super::apply::apply`], so the same [`super::entry::decide`] policy that
//! guards `chm image build` — traversal, absolute paths, symlink escape,
//! setuid stripping — guards this too. The only new parsers are the two
//! container formats: `ar` (a 60-byte-header archive) and zip. Both are small,
//! forward-only, and bounded; both are in-tree so the bound checks are ours.
//!
//! Every artefact is pinned by URL **and** SHA-256, checked before a byte is
//! unpacked, exactly as `KERNEL_DEB_SHA256` pins the kernel. Fetching a
//! browser over an unverified channel is the class of bug fixed in v0.2.2.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

use flate2::read::DeflateDecoder;
use ring::digest::{digest, SHA256};

use super::entry::{EntryKind, RawEntry};
use super::initramfs::Rootfs;
use super::targz::{Layer, TarEntry};
use crate::imp::human_bytes;

/// Where the browser lands in the guest. Under `/opt` because it is neither
/// distribution-managed nor something a user of this image is expected to
/// replace.
pub const GUEST_DIR: &str = "opt/gimbal-browser";

/// The generated launch script, and the image's entrypoint.
///
/// The entrypoint is interpolated into the init **unquoted** by design (it may
/// legitimately be `/bin/sh -c '…'`), so pointing it at a single path with no
/// metacharacters is the whole reason the browser flags live in a file rather
/// than on the entrypoint line.
pub const LAUNCH_PATH: &str = "opt/gimbal-browser/start";

/// The directory the Playwright zip puts everything under, and which is
/// stripped so the browser lands in [`GUEST_DIR`] rather than one level below
/// it.
const ARCHIVE_ROOT: &str = "chrome-linux";

/// The CDP port. Chromium's own default, so nothing on the Playwright side has
/// to be told about it.
pub const CDP_PORT: u16 = 9222;

/// The prefix every line the launcher prints carries, so a reader of a console
/// log can tell our words from Chromium's.
pub const LOG_TAG: &str = "gimbal-browser";

/// Printed, followed by the seconds it took, once CDP answers.
///
/// A machine-readable marker rather than prose because the app and #332 both
/// need to know when to connect, and "wait a bit longer" is how flaky tests
/// are made.
pub const READY_MARKER: &str = "gimbal-browser: CDP ready after";

/// Printed when the browser did not come up. Distinct from [`READY_MARKER`] on
/// purpose: a caller must be able to stop waiting, and a guest that has failed
/// looks exactly like a guest that is slow until it says which it is.
pub const FAILED_MARKER: &str = "gimbal-browser: FAILED:";

/// How long the launcher will wait for its own CDP endpoint, in seconds.
///
/// Generous against the measured cold start, because the cost of being wrong
/// is asymmetric: waiting a few seconds too long is invisible, giving up a
/// second too early turns a working guest into a mystery.
pub const READY_DEADLINE_SECS: u32 = 90;

/// The unprivileged user the browser runs as when the kernel allows it.
///
/// 65432 rather than 1000: an image's own `/etc/passwd` may already use low
/// ids, and a collision would silently give the browser somebody else's
/// identity.
pub const RUN_UID: u32 = 65432;

/// Playwright build 1234 = Chromium 151.0.7922.34, which is what
/// `playwright-core` 1.62.1 pins (measured against its `browsers.json`).
///
/// Matching a *released* Playwright matters more than being current: #332's
/// contract is `connectOverCDP` from Playwright, and Playwright version-matches
/// its own browser build.
pub const BROWSER_REVISION: &str = "1234";
pub const BROWSER_VERSION: &str = "151.0.7922.34";
pub const PLAYWRIGHT_VERSION: &str = "1.62.1";

pub const BROWSER_URL: &str = "https://cdn.playwright.dev/dbazure/download/playwright/builds/\
                               chromium/1234/chromium-headless-shell-linux-arm64.zip";
pub const BROWSER_SHA256: &str = "b03443e1e1a60d06e07b6cdfe650b8c2bfcbb3db497d2b652f73dc6912f4ae15";

/// Default guest RAM for a browser sandbox, in MiB.
///
/// Not a guess: the browser's own footprint was measured at ~236-270 MB
/// resident while idle, and `/dev/shm` is an unsized tmpfs that Chromium's
/// renderers use for shared buffers -- an unsized tmpfs is capped at half of
/// guest RAM, so RAM has to cover both the processes and the shared memory
/// they page through it.
///
/// The ceiling this sits under is [`crate::coldboot::MAX_MEMORY_MIB`], which
/// is a hard limit of the guest's physical layout rather than a policy. This
/// value leaves headroom under it deliberately: a browser that grows into its
/// last megabyte has nowhere to go, and the failure would be an OOM kill of a
/// renderer rather than an honest refusal.
pub const RAM_MIB: u64 = 2048;

///
/// Pinned to a tag rather than a digest deliberately: the 49 packages below are
/// what the browser actually links against, and they are pinned by content.
/// The base contributes `libc`, the dynamic loader and a shell, which is the
/// part that must match the packages' own build — so it moves with the release
/// they came from rather than being frozen against it.
pub const BASE_IMAGE: &str = "ubuntu:24.04";

/// The pool every runtime library is fetched from. Shared rather than repeated
/// 49 times so there is exactly one place the scheme can be wrong, and so the
/// "everything is HTTPS" guard has a single thing to check.
pub const UBUNTU_POOL: &str = "https://ports.ubuntu.com/ubuntu-ports/pool/";

/// One artefact, pinned.
#[derive(Debug, Clone, Copy)]
pub struct Pinned {
    /// Path under [`UBUNTU_POOL`].
    pub path: &'static str,
    pub sha256: &'static str,
}

impl Pinned {
    pub fn url(&self) -> String {
        format!("{UBUNTU_POOL}{}", self.path)
    }

    /// The file name, percent-decoded: Ubuntu's pool escapes `:` and `+` in
    /// versions, and a cache entry named `libnss3_2%3a3.98…` is a different
    /// file from the one apt would have written.
    pub fn file_name(&self) -> String {
        let raw = self.path.rsplit('/').next().unwrap_or(self.path);
        percent_decode(raw)
    }
}

/// The shared libraries `headless_shell` links against, plus their transitive
/// `Depends`, plus `ca-certificates`, `fonts-liberation` and `curl`.
///
/// Resolved rather than guessed: `apt-get install --no-install-recommends
/// --print-uris` inside an arm64 `ubuntu:24.04` container, seeded from the 27
/// `DT_NEEDED` entries read out of `headless_shell` itself. Sorted by file name
/// so a re-resolution produces a reviewable diff.
///
/// `curl` is here for one reason: the acceptance criterion of #331 is
/// `curl -s localhost:9222/json/version` **from inside the guest**, and a
/// readiness probe the image cannot run is not a readiness probe. It costs 15
/// of these 49 packages (2.16 MB compressed, measured) because libcurl depends
/// on krb5, LDAP, SASL and rtmp; against a 340 MB browser that is 0.6%, and it
/// is the price of the guest being able to answer for itself.
pub const RUNTIME_DEBS: &[Pinned] = &[
    Pinned {
        path: "main/a/at-spi2-core/at-spi2-common_2.52.0-1build1_all.deb",
        sha256: "7e05959b067031468f21ae46c6653a6813f1dccd994ef12a0b5f75de0ed346b6",
    },
    Pinned {
        path: "main/c/ca-certificates/ca-certificates_20240203_all.deb",
        sha256: "641de77d8f142cfd62a1a6f964ba67b20754d3337c480efb529d086075a06c9a",
    },
    Pinned {
        path: "main/c/curl/curl_8.5.0-2ubuntu10_arm64.deb",
        sha256: "0702def7b063d95208f060aafc9c04102ca805ee6a10008e42b9dee2b3f236c7",
    },
    Pinned {
        path: "main/f/fonts-liberation/fonts-liberation_2.1.5-3_all.deb",
        sha256: "065c2ab1abc9108b17d401016dc594b79750904390f095845c93bb06e1153acc",
    },
    Pinned {
        path: "main/a/alsa-lib/libasound2-data_1.2.11-1build2_all.deb",
        sha256: "a9e6326591ad5867f0783367f4708f145627ec95edfd8124d70d78b7516db4f1",
    },
    Pinned {
        path: "main/a/alsa-lib/libasound2t64_1.2.11-1build2_arm64.deb",
        sha256: "793a0961cad1540bdc6217f14b544eb1b27eda952675f4d7d150f547f0c196d7",
    },
    Pinned {
        path: "main/a/at-spi2-core/libatk1.0-0t64_2.52.0-1build1_arm64.deb",
        sha256: "8939633b3912c6476f3f501c2e8aa0fcc681dbd343b0a8138bf0ed5af8e9a77a",
    },
    Pinned {
        path: "main/a/at-spi2-core/libatspi2.0-0t64_2.52.0-1build1_arm64.deb",
        sha256: "c65f137507a665c969f9d158c8f63188b308037e66b48bca85ea2e7cf31bb84e",
    },
    Pinned {
        path: "main/b/brotli/libbrotli1_1.1.0-2build2_arm64.deb",
        sha256: "cabf3462d908e72f2e594f19ae87c581c4614f099947e38fbd865bf8eae27014",
    },
    Pinned {
        path: "main/libb/libbsd/libbsd0_0.12.1-1build1_arm64.deb",
        sha256: "6200ae28cdd976f9bf98571e4f7d49f9c632cfbc7eba241a3fed0f21ec8fe3ca",
    },
    Pinned {
        path: "main/c/curl/libcurl4t64_8.5.0-2ubuntu10_arm64.deb",
        sha256: "6411e90b37dc7cc96dde9efcc08c7a50615a8e10a783d892698d0171cbff8a0d",
    },
    Pinned {
        path: "main/d/dbus/libdbus-1-3_1.14.10-4ubuntu4_arm64.deb",
        sha256: "c269be28a2ed45d08f85ca2e7eb8a333f7ef5b01a052f4ad561e6834fe4c8964",
    },
    Pinned {
        path: "main/libd/libdrm/libdrm-common_2.4.120-2build1_all.deb",
        sha256: "84d60f8726a47b57c2ba9bd4105d838ff8554b7309035a61543e2bee4ed7914a",
    },
    Pinned {
        path: "main/libd/libdrm/libdrm2_2.4.120-2build1_arm64.deb",
        sha256: "ca73373d35a95c7c912d638fe14c543054e937ef63b8459665c3b70c83ee3f22",
    },
    Pinned {
        path: "main/e/expat/libexpat1_2.6.1-2build1_arm64.deb",
        sha256: "f6cea0cbe617519480ab3501166eab7092a9a75332cb186c30eee8107da381b9",
    },
    Pinned {
        path: "main/m/mesa/libgbm1_24.0.5-1ubuntu1_arm64.deb",
        sha256: "8589f317e7dacff6b958b9a2395fda3c9d62304b3da1390a53adbdb3afb33436",
    },
    Pinned {
        path: "main/g/glib2.0/libglib2.0-0t64_2.80.0-6ubuntu1_arm64.deb",
        sha256: "752ba1420f11452a2c3c9c8b8a68988defc4ea39d2d26a0372676722a27ebe0c",
    },
    Pinned {
        path: "main/k/krb5/libgssapi-krb5-2_1.20.1-6ubuntu2_arm64.deb",
        sha256: "27d6f3321a5b126ff1cfa76399506bb11e53ac38b5d263c3acdae2452356932d",
    },
    Pinned {
        path: "main/k/krb5/libk5crypto3_1.20.1-6ubuntu2_arm64.deb",
        sha256: "6b372dcd362202fba55fe40dabc9e6216fb96757b3f908a0056049fd1d3e6706",
    },
    Pinned {
        path: "main/k/keyutils/libkeyutils1_1.6.3-3build1_arm64.deb",
        sha256: "d141e94ed3b32ea6540f2e927a83b3d42cd4378256a1aad60cda583ffdbd78af",
    },
    Pinned {
        path: "main/k/krb5/libkrb5-3_1.20.1-6ubuntu2_arm64.deb",
        sha256: "45f2427ee2de6006348e6acfc6f104a4624fbe8577275ce7ab6a9a510842cdc3",
    },
    Pinned {
        path: "main/k/krb5/libkrb5support0_1.20.1-6ubuntu2_arm64.deb",
        sha256: "f24500abe0707ad5f16371e9f511d48923d8378f240afe9caa77a91b4854a95a",
    },
    Pinned {
        path: "main/o/openldap/libldap2_2.6.7%2bdfsg-1%7eexp1ubuntu8_arm64.deb",
        sha256: "296e93e99af40c59050b0b18e51de3e0bf85c713936b4ced9dbede799f61298a",
    },
    Pinned {
        path: "main/n/nghttp2/libnghttp2-14_1.59.0-1build4_arm64.deb",
        sha256: "65ff3fdec8eb72301d652f7d05887c8366a988606d933217e0b50294f012ec87",
    },
    Pinned {
        path: "main/n/nspr/libnspr4_4.35-1.1build1_arm64.deb",
        sha256: "0bd5994126c41aa05aa380954a3cb2ae56a0a8ebe368a0e01a411fdcc0cb9c68",
    },
    Pinned {
        path: "main/n/nss/libnss3_3.98-1build1_arm64.deb",
        sha256: "8cf38786c8808bec1873758f71c8c634387677f16104ba4c5ce2485746c4ac96",
    },
    Pinned {
        path: "main/libp/libpsl/libpsl5t64_0.21.2-1.1build1_arm64.deb",
        sha256: "886d485c74567b855bcd19b6f353a769a08b58c111b2d8275a908a469c15d4bf",
    },
    Pinned {
        path: "main/r/rtmpdump/librtmp1_2.4%2b20151223.gitfa8646d.1-2build7_arm64.deb",
        sha256: "fb771b2743120d9d44ee9989fd485205680976f7bf89f2f1ac5df50238ea1db7",
    },
    Pinned {
        path: "main/c/cyrus-sasl2/libsasl2-2_2.1.28%2bdfsg1-5ubuntu3_arm64.deb",
        sha256: "7cce03f3c6731bb8dc22b4b657247b9c6a176d92c21b09fdbfa8ea24e1e50e7e",
    },
    Pinned {
        path: "main/c/cyrus-sasl2/libsasl2-modules-db_2.1.28%2bdfsg1-5ubuntu3_arm64.deb",
        sha256: "bf5766523b1035645199962fda669c13130146b7e563a579dff0a8f9a785cb0c",
    },
    Pinned {
        path: "main/s/sqlite3/libsqlite3-0_3.45.1-1ubuntu2_arm64.deb",
        sha256: "b71c08ea650c212b2c8fa5bbcef9957e5e85c8f5c484a85cfb8961a8271bf376",
    },
    Pinned {
        path: "main/libs/libssh/libssh-4_0.10.6-2build2_arm64.deb",
        sha256: "633cbff0912d85db99f50ec7fa2a61bea7a1b3252f5d4ef2a1bb53145f15611c",
    },
    Pinned {
        path: "main/w/wayland/libwayland-server0_1.22.0-2.1build1_arm64.deb",
        sha256: "2b6dec0d40070685f4ce346d20b064fc5e118a3149f30be88465251985b496ed",
    },
    Pinned {
        path: "main/libx/libx11/libx11-6_1.8.7-1build1_arm64.deb",
        sha256: "16d10ae5d27f1a0feb054001ff2b213b51acd29894f86ff088c31eebeba65fe3",
    },
    Pinned {
        path: "main/libx/libx11/libx11-data_1.8.7-1build1_all.deb",
        sha256: "9ae01f7747e7f479394c697c55acf11d3baf139e8e54b7c4adfb55ef9c50de08",
    },
    Pinned {
        path: "main/libx/libxau/libxau6_1.0.9-1build6_arm64.deb",
        sha256: "348d0732ff9571f95d6ff18373a93e827bfe00474d792ef5e9071e6dd618605c",
    },
    Pinned {
        path: "main/libx/libxcb/libxcb-randr0_1.15-1ubuntu2_arm64.deb",
        sha256: "d1dc1d06b42da9a332274e34121ff57c6f6c1c155e4fe726c652f80f392ed419",
    },
    Pinned {
        path: "main/libx/libxcb/libxcb1_1.15-1ubuntu2_arm64.deb",
        sha256: "5483e5d19bbfa28e961d951645944e7763e943262ac17e216b2870d83597f319",
    },
    Pinned {
        path: "main/libx/libxcomposite/libxcomposite1_0.4.5-1build3_arm64.deb",
        sha256: "94f0d6d602d00e9ac53d307509897672f1132c875e2576a06fd9f3dcd00dd81e",
    },
    Pinned {
        path: "main/libx/libxdamage/libxdamage1_1.1.6-1build1_arm64.deb",
        sha256: "6f54865fd13492e6bd9045e18c48270cd6c422c447c5531a17358a26748e5d50",
    },
    Pinned {
        path: "main/libx/libxdmcp/libxdmcp6_1.1.3-0ubuntu6_arm64.deb",
        sha256: "6b96dbbae4e515ac8f32d6dacfcb6afd1266118400a85ae7cb3f887895017f53",
    },
    Pinned {
        path: "main/libx/libxext/libxext6_1.3.4-1build2_arm64.deb",
        sha256: "1140abacd8d23cb83cc63fb9aebb15a201e2dddbf5ca79fd999c0cbd181d0088",
    },
    Pinned {
        path: "main/libx/libxfixes/libxfixes3_6.0.0-2build1_arm64.deb",
        sha256: "884fc6560c5a8bc91fb6b7d067f557d8088ccee86ad1974b6a57085ac121e8de",
    },
    Pinned {
        path: "main/libx/libxi/libxi6_1.8.1-1build1_arm64.deb",
        sha256: "aeeb74a6ff6ea16312fd8eb1988b1ddf32afbb4503ab7121763530ee700058e3",
    },
    Pinned {
        path: "main/libx/libxkbcommon/libxkbcommon0_1.6.0-1build1_arm64.deb",
        sha256: "4ef68b9d56971a3119f40684f52a200be5c7c1bf8c5ef430a2d502e910bf8b61",
    },
    Pinned {
        path: "main/libx/libxrandr/libxrandr2_1.5.2-2build1_arm64.deb",
        sha256: "7470632764f1fde987e760850c2be58973e265f41b2bb8015c415d247898d2c4",
    },
    Pinned {
        path: "main/libx/libxrender/libxrender1_0.9.10-1.1build1_arm64.deb",
        sha256: "0a3aedab15d9b0d7a74b0b043676f0caacc104f188be16a008196dbc20e9e2e2",
    },
    Pinned {
        path: "main/o/openssl/openssl_3.0.13-0ubuntu3_arm64.deb",
        sha256: "9b7136b1af32fbdefc2eac61bae86f8304c603c7b9a0297b20a1e31c522b024b",
    },
    // iproute2 and its closure. Not for the browser: the generated init brings
    // `lo` up with `ip` or `ifconfig`, and `ubuntu:24.04` ships neither -- so
    // without this the loopback interface stays down, Chromium's DevTools
    // server fails `bind(): Cannot assign requested address (99)`, and the
    // readiness probe for `127.0.0.1` is routed out of the NIC and denied by
    // chm's own egress policy. All three were measured in one boot.
    Pinned {
        path: "main/e/elfutils/libelf1t64_0.190-1.1ubuntu0.1_arm64.deb",
        sha256: "ba200bd93e3a1ade40e2c71540f55e7016c60f11e1b9fe1a76ef975de99b87f5",
    },
    Pinned {
        path: "main/libb/libbpf/libbpf1_1.3.0-2build2_arm64.deb",
        sha256: "bd7e0d87cdf6363691abd7b4470b5e43dc8cb91b874f054f6efd9421a7a88099",
    },
    Pinned {
        path: "main/libm/libmnl/libmnl0_1.0.5-2build1_arm64.deb",
        sha256: "9442f15a4bbc6148e527045adaf85c86ae3ffe159176d6a5f3b471b49150e470",
    },
    Pinned {
        path: "main/i/iptables/libxtables12_1.8.10-3ubuntu2_arm64.deb",
        sha256: "72cd6add0f8eaaa45f44dd5c0903df083ab3847091d0633b4e46e8f80443718a",
    },
    Pinned {
        path: "main/libc/libcap2/libcap2-bin_2.66-5ubuntu2.4_arm64.deb",
        sha256: "6c9cac86db2d4e0d7eebe8a79ceade3623ab91670a5a348a6efb7abed0abce06",
    },
    Pinned {
        path: "main/i/iproute2/iproute2_6.1.0-1ubuntu6.4_arm64.deb",
        sha256: "5cc0bfac0a176309c10c6ef2796c550c6a0ecfc53b9f428b4a632b4f4a2ce8df",
    },
    Pinned {
        path: "main/x/xkeyboard-config/xkb-data_2.41-2ubuntu1_all.deb",
        sha256: "5f0a5188398b606d723f1bed48ee38c11eaeb98357ab29a3bf33c451056815d1",
    },
];

/// Files removed from the assembled rootfs, and why.
///
/// This list is the load-bearing half of "a browser and nothing else". Every
/// entry is something that would let whoever reaches CDP turn the guest into
/// something more than a browser, or that exists only to serve a package
/// manager we have just established the image will never run.
///
/// Each entry matches a rootfs-relative path exactly, and matches everything
/// beneath it when it names a directory. It is deliberately **not** a glob:
/// `usr/bin/apt` removing `usr/bin/apt-get` by accident of prefix would also
/// have removed anything else beginning "apt", and a removal list that is
/// approximately right is worse than one that is explicit and long.
///
/// The cost of being explicit is that a future release could add a tool this
/// list does not name. That is what [`audit`] is for: it re-derives the
/// question from the *shape* of what survived, and fails the build rather than
/// shipping an image whose central claim is false.
pub const REMOVED: &[(&str, &str)] = &[
    // apt, enumerated from `ubuntu:24.04` arm64.
    ("usr/bin/apt", "the package manager"),
    ("usr/bin/apt-cache", "the package manager"),
    ("usr/bin/apt-cdrom", "the package manager"),
    ("usr/bin/apt-config", "the package manager"),
    ("usr/bin/apt-get", "the package manager"),
    ("usr/bin/apt-key", "the package manager"),
    ("usr/bin/apt-mark", "the package manager"),
    ("usr/lib/apt", "apt's own methods, including http(s)"),
    ("etc/apt", "where to get more software"),
    ("var/lib/apt", "the package lists"),
    ("var/cache/apt", "the package cache"),
    // dpkg, likewise. `dpkg-deb` alone is enough to unpack anything fetched
    // by any other means, so the family goes as a family.
    ("usr/bin/dpkg", "the package manager"),
    ("usr/bin/dpkg-deb", "unpacks a package without apt"),
    ("usr/bin/dpkg-divert", "the package manager"),
    ("usr/bin/dpkg-maintscript-helper", "the package manager"),
    ("usr/bin/dpkg-query", "the package manager"),
    ("usr/bin/dpkg-realpath", "the package manager"),
    ("usr/bin/dpkg-split", "reassembles a split package"),
    ("usr/bin/dpkg-statoverride", "the package manager"),
    ("usr/bin/dpkg-trigger", "the package manager"),
    ("usr/sbin/dpkg-preconfigure", "the package manager"),
    ("usr/sbin/dpkg-reconfigure", "the package manager"),
    ("usr/lib/dpkg", "the package manager"),
    ("var/lib/dpkg", "the package database"),
    // debconf exists only to answer a package manager's questions.
    ("usr/bin/debconf", "serves the package manager"),
    ("usr/bin/debconf-apt-progress", "serves the package manager"),
    ("usr/bin/debconf-communicate", "serves the package manager"),
    ("usr/bin/debconf-copydb", "serves the package manager"),
    ("usr/bin/debconf-escape", "serves the package manager"),
    (
        "usr/bin/debconf-set-selections",
        "serves the package manager",
    ),
    ("usr/bin/debconf-show", "serves the package manager"),
    ("usr/share/debconf", "serves the package manager"),
    ("var/cache/debconf", "serves the package manager"),
    // Weight with no reader in a guest that has no shell session.
    ("usr/share/doc", "documentation no guest reads"),
    ("usr/share/doc-base", "packaging metadata"),
    ("usr/share/man", "manual pages no guest reads"),
    ("usr/share/lintian", "packaging metadata"),
    ("usr/share/bug", "packaging metadata"),
];

/// Path fragments that must not survive [`strip`], and what each one would
/// mean if it did.
///
/// This is the independent half of the check. [`REMOVED`] is a list of names
/// someone wrote down; this asks what *shape* of thing is present, so a tool
/// that arrives in a future base image is caught by the property rather than
/// by anyone having predicted it.
///
/// Matched against the final path component, so `usr/share/doc/apt/NEWS` does
/// not count as "apt survived" -- it is a file called `NEWS`.
const FORBIDDEN_BASENAMES: &[(&str, &str)] = &[
    ("apt", "a package manager could install anything"),
    ("dpkg", "a package manager could install anything"),
    ("debconf", "it exists only to serve a package manager"),
    ("sshd", "a remote shell dissolves the whole argument"),
    ("dropbear", "a remote shell dissolves the whole argument"),
    ("telnetd", "a remote shell dissolves the whole argument"),
];

/// Every executable-looking path that contradicts "a browser and nothing else".
///
/// Run after [`strip`], and a non-empty answer fails the build. The point is
/// that the image's central security claim is *checked* rather than asserted:
/// the argument for exposing a CDP port at all is that there is nothing else
/// in the guest, so the build should not be able to ship an image where that
/// is untrue without saying so.
pub fn audit(rootfs: &Rootfs) -> Vec<String> {
    let mut found = Vec::new();
    for path in rootfs.paths() {
        // Only executables in a place something would be run from. A library
        // called `libapt-pkg.so` is inert; `usr/bin/apt-get` is not.
        if !(path.starts_with("usr/bin/")
            || path.starts_with("usr/sbin/")
            || path.starts_with("bin/")
            || path.starts_with("sbin/"))
        {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        for (bad, why) in FORBIDDEN_BASENAMES {
            // Exact, or the Debian tool-family form `dpkg-deb`. A basename
            // that merely contains the word -- `aptitude-create-state-bundle`
            // -- is a different program and is not what this is asking about.
            if base == *bad || base.starts_with(&format!("{bad}-")) {
                found.push(format!("{path}: {why}"));
            }
        }
    }
    found
}

/// Percent-decode, tolerating anything that is not a valid escape by leaving it
/// alone. Ubuntu's pool only ever escapes `:` and `+`, so this is narrow on
/// purpose: it decodes file names, and is never used to build a path we open.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Lowercase hex of the SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Where downloads are kept between builds.
///
/// A browser image is ~350 MB of download; re-fetching it on every build would
/// make iterating on this feature miserable and would hammer a CDN we do not
/// own.
pub fn cache_dir() -> PathBuf {
    if let Some(v) = env::var_os("GIMBAL_BROWSER_CACHE") {
        return PathBuf::from(v);
    }
    let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("gimbal-images").join(".browser-cache")
}

/// Fetch `url`, verify it against `sha256`, and cache it under `name`.
///
/// The digest is checked on **every** path, including the cache hit. A cache is
/// a directory on a machine the guest's contents are being assembled from; a
/// build that trusts it because it wrote it once is a build that can be
/// poisoned by anything else that can write there.
pub fn fetch(url: &str, sha256: &str, name: &str, cache: &Path) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err(format!(
            "refusing to fetch `{url}`: browser artefacts are fetched over HTTPS only"
        ));
    }
    let path = cache.join(name);
    if let Ok(bytes) = fs::read(&path) {
        let got = sha256_hex(&bytes);
        if got == sha256 {
            return Ok(bytes);
        }
        // Not fatal: a truncated download is the common cause, and re-fetching
        // is what a user would do anyway. Said out loud because the other
        // cause is somebody writing into the cache.
        eprintln!(
            "  cache entry {} has the wrong digest (expected {sha256}, got {got}); re-fetching",
            path.display()
        );
    }
    fs::create_dir_all(cache).map_err(|e| format!("create {}: {e}", cache.display()))?;
    let out = Command::new("curl")
        .arg("-sSL")
        .args(["--max-time", "900"])
        .args(["--fail", "--proto", "=https", "--tlsv1.2"])
        .arg("-o")
        .arg(&path)
        .arg(url)
        .output()
        .map_err(|e| format!("spawn curl: {e} (is curl installed?)"))?;
    if !out.status.success() {
        let _ = fs::remove_file(&path);
        return Err(format!(
            "downloading {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let got = sha256_hex(&bytes);
    if got != sha256 {
        // Removed rather than left behind: a file on disk with the right name
        // and the wrong contents is the thing the next build would find.
        let _ = fs::remove_file(&path);
        return Err(format!(
            "{url} does not match its pinned digest.\n  expected sha256:{sha256}\n  \
             got      sha256:{got}\nNothing was unpacked. Either the pin is stale or the \
             download was tampered with; both need a human."
        ));
    }
    Ok(bytes)
}

/// Return the `data.tar.*` member of a `.deb`.
///
/// A `.deb` is a `!<arch>` archive of exactly three members in order:
/// `debian-binary`, `control.tar.*`, `data.tar.*`. Only the third is wanted.
/// Headers are fixed 60 bytes with space-padded decimal fields, and members are
/// padded to an even offset — the padding rule is the one thing that silently
/// yields garbage if forgotten, because it only bites on odd-sized members.
pub fn deb_data_member(deb: &[u8]) -> Result<&[u8], String> {
    const MAGIC: &[u8] = b"!<arch>\n";
    const HEADER: usize = 60;
    if !deb.starts_with(MAGIC) {
        return Err("not an ar archive: a .deb must start with `!<arch>`".to_string());
    }
    let mut off = MAGIC.len();
    while off + HEADER <= deb.len() {
        let header = &deb[off..off + HEADER];
        if &header[58..60] != b"`\n" {
            return Err(format!("malformed ar header at offset {off}"));
        }
        let name = String::from_utf8_lossy(&header[0..16])
            .trim_end()
            .trim_end_matches('/')
            .to_string();
        let size: usize = String::from_utf8_lossy(&header[48..58])
            .trim()
            .parse()
            .map_err(|_| format!("ar member `{name}` has an unreadable size"))?;
        let start = off + HEADER;
        let end = start
            .checked_add(size)
            .filter(|e| *e <= deb.len())
            .ok_or_else(|| format!("ar member `{name}` runs past the end of the archive"))?;
        if name.starts_with("data.tar") {
            return Ok(&deb[start..end]);
        }
        // Members are padded to an even offset; the padding byte is not counted
        // in the size.
        off = end + (end % 2);
    }
    Err("this .deb carries no data.tar member".to_string())
}

/// One zip entry, as far as we read them.
struct ZipEntry {
    name: String,
    mode: u32,
    data: Vec<u8>,
}

/// Read a zip via its **central directory**, which is the authoritative index;
/// local headers are a convenience for streaming and may disagree with it.
///
/// Deliberately narrow: store and deflate only, no zip64, no encryption, no
/// data descriptors. The Playwright archive is 12 entries, 2 stored and 10
/// deflated, no zip64 (measured). Anything outside that is refused rather than
/// guessed at, because every guess here is a guess about attacker-controlled
/// bytes.
fn read_zip(zip: &[u8], limit_bytes: u64) -> Result<Vec<ZipEntry>, String> {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const LOCAL_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

    let le16 = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as usize;
    let le32 =
        |b: &[u8], o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize;

    // The end-of-central-directory record is last, but may be followed by a
    // comment, so it is searched for backwards over the maximum comment length.
    let scan_from = zip.len().saturating_sub(66_000);
    let eocd = (scan_from..zip.len().saturating_sub(21))
        .rev()
        .find(|i| zip[*i..*i + 4] == EOCD_SIG)
        .ok_or("not a zip archive: no end-of-central-directory record")?;
    let count = le16(zip, eocd + 10);
    let cd_size = le32(zip, eocd + 12);
    let cd_off = le32(zip, eocd + 16);
    if cd_off.saturating_add(cd_size) > zip.len() {
        return Err("zip central directory runs past the end of the file".to_string());
    }

    let mut out = Vec::with_capacity(count);
    let mut total: u64 = 0;
    let mut p = cd_off;
    for _ in 0..count {
        if p + 46 > zip.len() || zip[p..p + 4] != CD_SIG {
            return Err(format!("malformed zip central directory entry at {p}"));
        }
        let method = le16(zip, p + 10);
        let comp_size = le32(zip, p + 20);
        let uncomp_size = le32(zip, p + 24);
        let name_len = le16(zip, p + 28);
        let extra_len = le16(zip, p + 30);
        let comment_len = le16(zip, p + 32);
        let external = le32(zip, p + 38);
        let local = le32(zip, p + 42);
        let name_end = p + 46 + name_len;
        if name_end > zip.len() {
            return Err("zip entry name runs past the end of the file".to_string());
        }
        let name = String::from_utf8_lossy(&zip[p + 46..name_end]).into_owned();
        p = name_end + extra_len + comment_len;

        total = total.saturating_add(uncomp_size as u64);
        if total > limit_bytes {
            return Err(format!(
                "the browser archive unpacks to more than {limit_bytes} bytes; refusing"
            ));
        }

        // The local header repeats the name and extra fields with its own
        // lengths, and the data begins after them. Its *lengths* are read here
        // (they are what locate the data) while its sizes are ignored in favour
        // of the central directory's.
        if local + 30 > zip.len() || zip[local..local + 4] != LOCAL_SIG {
            return Err(format!("zip entry `{name}` has no local header"));
        }
        let lname = le16(zip, local + 26);
        let lextra = le16(zip, local + 28);
        let start = local + 30 + lname + lextra;
        let end = start
            .checked_add(comp_size)
            .filter(|e| *e <= zip.len())
            .ok_or_else(|| format!("zip entry `{name}` runs past the end of the file"))?;
        let raw = &zip[start..end];

        let data = match method {
            0 => raw.to_vec(),
            8 => {
                let mut buf = Vec::with_capacity(uncomp_size);
                DeflateDecoder::new(raw)
                    .take(limit_bytes)
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("zip entry `{name}` would not inflate: {e}"))?;
                buf
            }
            other => {
                return Err(format!(
                    "zip entry `{name}` uses compression method {other}; only store and \
                     deflate are supported"
                ))
            }
        };
        if data.len() != uncomp_size {
            return Err(format!(
                "zip entry `{name}` inflated to {} bytes, not the {uncomp_size} it declared",
                data.len()
            ));
        }
        // The high 16 bits of the external attributes are the Unix mode when
        // the archive was made on Unix. Playwright's is, and the executable bit
        // on `headless_shell` is the whole point; a default is used rather than
        // trusting a zero, because a mode of 0 is indistinguishable from
        // "written by a tool that does not record modes".
        let unix = (external >> 16) & 0o7777;
        let is_dir = name.ends_with('/');
        let mode = if unix != 0 {
            unix as u32
        } else if is_dir {
            0o755
        } else {
            0o644
        };
        out.push(ZipEntry { name, mode, data });
    }
    Ok(out)
}

/// The browser zip, as a layer that lands under [`GUEST_DIR`].
///
/// The archive's own top-level directory is `chrome-linux/`; it is rewritten
/// rather than kept, so the guest path is ours and does not change if
/// Playwright renames theirs.
pub fn browser_layer(zip: &[u8], limit_bytes: u64) -> Result<Layer, String> {
    let entries = read_zip(zip, limit_bytes)?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let name = e.name.trim_end_matches('/');
        // The archive's own root directory carries nothing, and everything
        // below it is remapped out from under it -- so letting it through
        // would create an empty `opt/gimbal-browser/chrome-linux` beside the
        // files it used to hold.
        if name.is_empty() || name == ARCHIVE_ROOT {
            continue;
        }
        let rel = name
            .strip_prefix(ARCHIVE_ROOT)
            .and_then(|r| r.strip_prefix('/'))
            .unwrap_or(name);
        let is_dir = e.name.ends_with('/');
        let path = format!("{GUEST_DIR}/{rel}");
        let kind = if is_dir {
            EntryKind::Directory { mode: e.mode }
        } else {
            EntryKind::File {
                mode: e.mode,
                size: e.data.len() as u64,
            }
        };
        out.push(TarEntry {
            raw: RawEntry { path, kind },
            data: e.data,
        });
    }
    if out.is_empty() {
        return Err("the browser archive held no files under chrome-linux/".to_string());
    }
    Ok(Layer {
        entries: out,
        skipped: Vec::new(),
    })
}

/// The script the guest boots into.
///
/// # The sandbox
///
/// Chromium refuses to run as root without `--no-sandbox` (measured:
/// `zygote_host_impl_linux.cc:101`). The better answer is not to be root: if
/// the kernel will give us an unprivileged user namespace, the browser drops to
/// [`RUN_UID`] and keeps its own sandbox, which is a materially stronger story
/// than a VM boundary alone.
///
/// Both paths are kept because only one of them is available on any given
/// kernel, and the script cannot know which at build time. It **probes** rather
/// than assuming, and says which branch it took, so the answer is in the boot
/// log rather than in someone's memory.
///
/// # `/dev/shm`
///
/// The generated init mounts `/proc`, `/sys`, `/dev` and `/tmp` but not
/// `/dev/shm`, and Chromium uses shared memory for every renderer surface.
/// Mounted here with no `size=`, which gives the tmpfs default of half of guest
/// RAM — deliberately not the 64 MB a container gets, which is the well-known
/// cause of `--disable-dev-shm-usage` existing at all.
///
/// # Why it reports readiness instead of just `exec`ing
///
/// This guest has no shell session on the console — that is the point of the
/// image, and it is also what makes it hard to check. So the launcher answers
/// the question itself: it polls its own CDP endpoint and prints the reply,
/// which is both the acceptance criterion of #331 and the signal a client
/// needs in order to know when to connect. A caller that guesses how long a
/// browser takes to start is a caller that has a flaky test.
///
/// The probe is `curl --max-time`, never a raw socket read. Chrome's DevTools
/// HTTP endpoint does not close the connection on `Connection: close`, so a
/// read without a deadline hangs forever; that cost this project 1h49m once
/// already and is not going to cost it twice.
pub fn launch_script() -> String {
    format!(
        r#"#!/bin/sh
# Generated by `chm image build --browser` -- V11.2, #331.
#
# This is the whole of the guest's userland behaviour: mount what the browser
# needs, drop privilege if the kernel allows it, start the browser, say when
# CDP answers, and then do nothing else for the rest of the guest's life.
# There is deliberately no supervisor, no exec endpoint and no second service.

mkdir -p /dev/shm 2>/dev/null
mount -t tmpfs tmpfs /dev/shm 2>/dev/null

PROFILE=/var/lib/gimbal-browser
mkdir -p "$PROFILE" 2>/dev/null

# Chromium's fontconfig and its own caches follow $HOME, and PID 1 does not
# have one. Left unset the guest prints six `No writable cache directories`
# errors per start and rebuilds the font cache on every boot -- measured, and
# noise in a console log is how a real failure gets missed.
HOME="$PROFILE"
XDG_CACHE_HOME="$PROFILE/.cache"
XDG_CONFIG_HOME="$PROFILE/.config"
export HOME XDG_CACHE_HOME XDG_CONFIG_HOME
mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" 2>/dev/null

# The DevTools HTTP server binds 127.0.0.1 and there is no flag to change it.
#
# Measured, twice, rather than assumed: `strings` on this build lists only
# `remote-debugging-port` and `remote-debugging-pipe` -- there is no
# `remote-debugging-address` switch in chromium-headless-shell 151 -- and
# passing one anyway leaves /proc/net/tcp showing `0100007F:2406`, which is
# 127.0.0.1:9222.
#
# So this guest serves CDP to itself. Reaching it from the host needs a
# forwarder inside the guest that this image deliberately does not yet carry;
# see the note in docs/container-images.md.
set -- --remote-debugging-port={port} \
    --user-data-dir="$PROFILE" \
    --disable-gpu \
    --no-first-run \
    --no-default-browser-check

# Can this kernel give an unprivileged process a user namespace? That is what
# Chromium's own sandbox needs, and it is a property of the kernel rather than
# of the image -- so it is measured here rather than decided at build time.
if unshare --user --map-root-user true 2>/dev/null; then
    echo "{tag}: user namespaces work; running sandboxed as uid {uid}"
    chown -R {uid} "$PROFILE" 2>/dev/null
    setpriv --reuid={uid} --regid={uid} --clear-groups \
        {dir}/headless_shell "$@" &
else
    # Running as root, so Chromium refuses to start with a sandbox at all. The
    # VM is still the security boundary, which is the premise of #329 -- but
    # this is the weaker of the two paths and says so rather than passing the
    # flag quietly.
    echo "{tag}: no unprivileged user namespace; running as root with"
    echo "{tag}: --no-sandbox. The VM boundary is the only isolation here."
    {dir}/headless_shell --no-sandbox "$@" &
fi
browser=$!

# Poll rather than sleep. `--max-time` on every request, so a wedged endpoint
# costs two seconds instead of the rest of the boot.
i=0
while [ $i -lt {deadline} ]; do
    version=$(curl -sS --max-time 2 \
        http://127.0.0.1:{port}/json/version 2>/dev/null)
    case "$version" in
        *webSocketDebuggerUrl*)
            echo "{ready} $i"
            echo "$version"
            break
            ;;
    esac
    # Nothing to wait for if the browser is already gone; say so now rather
    # than spending the whole deadline on a process that has exited.
    kill -0 "$browser" 2>/dev/null || {{
        echo "{failed} the browser exited before CDP answered"
        break
    }}
    i=$((i + 1))
    sleep 1
done
[ $i -lt {deadline} ] || echo "{failed} CDP did not answer within {deadline}s"

# PID 1's child, and the only thing this guest does from here on.
wait "$browser"
echo "{failed} the browser exited with status $?"
"#,
        port = CDP_PORT,
        uid = RUN_UID,
        dir = format_args!("/{GUEST_DIR}"),
        tag = LOG_TAG,
        ready = READY_MARKER,
        failed = FAILED_MARKER,
        deadline = READY_DEADLINE_SECS,
    )
}

/// A `/etc/passwd` line for [`RUN_UID`], appended to whatever the base image
/// shipped.
///
/// `setpriv --reuid` does not need the user to exist, but everything that later
/// asks "who am I" does, and a browser profile owned by a uid with no name is
/// the kind of detail that turns into a puzzling failure in P4's snapshot work.
pub fn passwd_line() -> String {
    format!("gimbal:x:{RUN_UID}:{RUN_UID}:gimbal browser:/var/lib/gimbal-browser:/bin/false\n")
}

/// What [`strip`] took back out, for the build to report.
#[derive(Debug, Default)]
pub struct Removed {
    pub paths: usize,
    pub bytes: u64,
}

/// Take the package manager and its bookkeeping back out of the rootfs.
///
/// Called **after** the layers are applied, so no ordering trick in an image
/// can reintroduce what this removes; and after the browser is installed, so
/// the thing that survives is the browser.
///
/// This is the subtraction the whole image is built around. A guest with `apt`
/// in it is a guest that can become anything, and then "the blast radius is a
/// browser" stops being true.
pub fn strip(rootfs: &mut Rootfs) -> Removed {
    let mut summary = Removed::default();
    for (prefix, _) in REMOVED {
        let victims: Vec<String> = rootfs
            .paths()
            .filter(|p| *p == *prefix || p.starts_with(&format!("{prefix}/")))
            .map(str::to_string)
            .collect();
        for v in victims {
            if let Some(node) = rootfs.get(&v) {
                summary.bytes += node.data.len() as u64;
            }
            summary.paths += 1;
            rootfs.whiteout(&v);
        }
    }
    summary
}

/// Install the launcher, the unprivileged user, and the profile directory.
///
/// Written straight into the rootfs rather than shipped as a layer because
/// these three are *ours*: no image content should be able to shadow the script
/// the guest boots into, which is exactly what would happen if they went
/// through [`super::apply::apply`] alongside the layers.
pub fn install(rootfs: &mut Rootfs) {
    let script = launch_script();
    rootfs.insert(
        rootfs.resolve_parents(LAUNCH_PATH),
        EntryKind::File {
            mode: 0o755,
            size: script.len() as u64,
        },
        script.into_bytes(),
    );

    // Appended, not written: dropping the base image's own `/etc/passwd` would
    // take `root` with it, and the init runs as root before it drops.
    let passwd_path = rootfs.resolve_parents("etc/passwd");
    let mut passwd = rootfs
        .get(&passwd_path)
        .map(|n| n.data.clone())
        .unwrap_or_default();
    if !passwd.is_empty() && !passwd.ends_with(b"\n") {
        passwd.push(b'\n');
    }
    passwd.extend_from_slice(passwd_line().as_bytes());
    rootfs.insert(
        passwd_path,
        EntryKind::File {
            mode: 0o644,
            size: passwd.len() as u64,
        },
        passwd,
    );

    rootfs.insert(
        rootfs.resolve_parents("var/lib/gimbal-browser"),
        EntryKind::Directory { mode: 0o755 },
        Vec::new(),
    );

    install_ca_bundle(rootfs);
}

/// Where the `ca-certificates` package's own configuration points every TLS
/// client on a Debian-family system.
const CA_BUNDLE: &str = "etc/ssl/certs/ca-certificates.crt";

/// The directory the individual trusted certificates are unpacked into.
const CA_SOURCE_DIR: &str = "usr/share/ca-certificates";

/// Concatenate the trusted roots into the bundle every TLS client looks for.
///
/// The `ca-certificates` package ships the certificates and then builds this
/// file from them in a `postinst`. Nothing runs maintainer scripts here, so
/// installing the package gets you the parts and not the thing: measured on
/// the assembled image, `/etc/ssl/certs/ca-certificates.crt` was absent and
/// `curl https://en.wikipedia.org/...` returned `000` from inside a booted
/// guest whose network was otherwise working -- Chromium loaded the same page
/// fine, because it carries its own root store.
///
/// That failure mode is worth closing rather than documenting: a TLS error
/// that looks like a network fault is how `-k` and `--no-check-certificate`
/// end up in scripts.
fn install_ca_bundle(rootfs: &mut Rootfs) {
    let prefix = format!("{CA_SOURCE_DIR}/");
    let mut bundle = Vec::new();
    let mut count = 0usize;
    // Path order, so the same input always produces byte-identical output.
    let certs: Vec<Vec<u8>> = rootfs
        .paths()
        .filter(|p| p.starts_with(&prefix) && p.ends_with(".crt"))
        .map(str::to_string)
        .collect::<Vec<_>>()
        .iter()
        .filter_map(|p| rootfs.get(p).map(|n| n.data.clone()))
        .collect();
    for cert in certs {
        if !cert.windows(2).any(|w| w == b"--") {
            continue;
        }
        bundle.extend_from_slice(&cert);
        if !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        count += 1;
    }
    if count == 0 {
        return;
    }
    rootfs.insert(
        rootfs.resolve_parents(CA_BUNDLE),
        EntryKind::File {
            mode: 0o644,
            size: bundle.len() as u64,
        },
        bundle,
    );
}

/// Fetch and read every pinned artefact, newest last.
///
/// The browser goes last so that if a library package and the browser ever
/// claimed the same path, the browser wins — it is the thing the image exists
/// for.
pub fn layers(cache: &Path, limit_bytes: u64) -> Result<Vec<Layer>, String> {
    let mut out = Vec::with_capacity(RUNTIME_DEBS.len() + 1);
    for (i, p) in RUNTIME_DEBS.iter().enumerate() {
        let name = p.file_name();
        let deb = fetch(&p.url(), p.sha256, &name, cache)?;
        let data = deb_data_member(&deb)?;
        let layer = super::image::read_blob(data, limit_bytes)
            .map_err(|e| format!("reading {name}: {e}"))?;
        if i == 0 || (i + 1) % 10 == 0 || i + 1 == RUNTIME_DEBS.len() {
            println!("  library {}/{}: {name}", i + 1, RUNTIME_DEBS.len());
        }
        out.push(layer);
    }
    let zip = fetch(
        BROWSER_URL,
        BROWSER_SHA256,
        "chromium-headless-shell-linux-arm64.zip",
        cache,
    )?;
    println!(
        "  browser: chromium-headless-shell {BROWSER_VERSION} \
         (Playwright build {BROWSER_REVISION}, as pinned by playwright-core \
         {PLAYWRIGHT_VERSION}), {} compressed",
        human_bytes(zip.len() as u64)
    );
    out.push(browser_layer(&zip, limit_bytes)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin discipline, which is the whole security argument for downloading
    /// a browser at all. Mutating any URL to http, or blanking a digest, fails
    /// here.
    #[test]
    fn every_artefact_is_pinned_over_https() {
        assert!(
            BROWSER_URL.starts_with("https://"),
            "the browser must be fetched over HTTPS: {BROWSER_URL}"
        );
        assert!(
            UBUNTU_POOL.starts_with("https://"),
            "the library pool must be HTTPS: {UBUNTU_POOL}"
        );
        assert_eq!(
            BROWSER_SHA256.len(),
            64,
            "the browser pin must be a full sha256"
        );
        for p in RUNTIME_DEBS {
            assert_eq!(
                p.sha256.len(),
                64,
                "`{}` is not pinned to a full sha256",
                p.path
            );
            assert!(
                p.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "`{}` has a non-hex digest",
                p.path
            );
            assert!(
                p.url().starts_with("https://"),
                "`{}` would be fetched over {}",
                p.path,
                p.url()
            );
        }
    }

    /// A duplicate pin means one of the two is dead and nobody would notice,
    /// which is how a stale library survives a version bump.
    #[test]
    fn no_artefact_is_pinned_twice() {
        let mut seen: Vec<&str> = RUNTIME_DEBS.iter().map(|p| p.path).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a package is pinned more than once");
    }

    #[test]
    fn fetch_refuses_plain_http() {
        let err = fetch(
            "http://example.invalid/x.deb",
            BROWSER_SHA256,
            "x.deb",
            Path::new("/nonexistent"),
        )
        .expect_err("http must be refused");
        assert!(err.contains("HTTPS"), "{err}");
    }

    #[test]
    fn pool_paths_are_percent_decoded_for_the_cache() {
        let p = Pinned {
            path: "main/n/nss/libnss3_2%3a3.98-1build1_arm64.deb",
            sha256: "0",
        };
        assert_eq!(p.file_name(), "libnss3_2:3.98-1build1_arm64.deb");
    }

    fn ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, body) in members {
            let mut header = vec![b' '; 60];
            header[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{}", body.len());
            header[48..48 + size.len()].copy_from_slice(size.as_bytes());
            header[58] = b'`';
            header[59] = b'\n';
            out.extend_from_slice(&header);
            out.extend_from_slice(body);
            if body.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn the_data_member_is_found_after_an_odd_sized_one() {
        // The padding rule only bites on an odd-sized member, so the fixture
        // makes `control.tar.zst` odd on purpose: without the `end % 2` the
        // next header lands one byte early and the archive reads as malformed.
        let deb = ar_archive(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.zst", b"odd"),
            ("data.tar.zst", b"PAYLOAD"),
        ]);
        assert_eq!(deb_data_member(&deb).expect("data member"), b"PAYLOAD");
    }

    #[test]
    fn a_deb_with_no_data_member_is_refused() {
        let deb = ar_archive(&[("debian-binary", b"2.0\n")]);
        let err = deb_data_member(&deb).expect_err("must refuse");
        assert!(err.contains("no data.tar"), "{err}");
    }

    #[test]
    fn something_that_is_not_an_ar_archive_is_refused() {
        let err = deb_data_member(b"not an archive at all").expect_err("must refuse");
        assert!(err.contains("!<arch>"), "{err}");
    }

    #[test]
    fn a_member_claiming_more_bytes_than_exist_is_refused() {
        let mut deb = ar_archive(&[("data.tar.zst", b"short")]);
        // Rewrite the size field to claim far more than the archive holds --
        // the read that would follow is the one this guards.
        let size_at = 8 + 48;
        deb[size_at..size_at + 10].copy_from_slice(b"9999999   ");
        let err = deb_data_member(&deb).expect_err("must refuse");
        assert!(err.contains("past the end"), "{err}");
    }

    /// A stored (uncompressed) zip, built by hand so the reader is tested
    /// against bytes rather than against another copy of itself.
    fn stored_zip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body, mode) in entries {
            let local = out.len() as u32;
            out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            out.extend_from_slice(&[0u8; 4]); // version, flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method: store
            out.extend_from_slice(&[0u8; 8]); // time, date, crc
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(body);

            central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
            central.extend_from_slice(&[0u8; 6]); // versions, flags
            central.extend_from_slice(&0u16.to_le_bytes()); // method
            central.extend_from_slice(&[0u8; 8]); // time, date, crc
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0u8; 8]); // extra, comment, disk, attrs
            central.extend_from_slice(&(mode << 16).to_le_bytes());
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn the_browser_lands_under_our_own_directory_with_its_mode() {
        let zip = stored_zip(&[
            ("chrome-linux/headless_shell", b"ELF", 0o755),
            ("chrome-linux/icudtl.dat", b"data", 0o644),
        ]);
        let layer = browser_layer(&zip, 1 << 20).expect("layer");
        let paths: Vec<&str> = layer.entries.iter().map(|e| e.raw.path.as_str()).collect();
        assert!(
            paths.contains(&"opt/gimbal-browser/headless_shell"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"opt/gimbal-browser/icudtl.dat"),
            "{paths:?}"
        );
        let shell = layer
            .entries
            .iter()
            .find(|e| e.raw.path.ends_with("headless_shell"))
            .expect("the browser");
        assert_eq!(
            shell.raw.kind,
            EntryKind::File {
                mode: 0o755,
                size: 3
            },
            "the browser must stay executable, or the guest boots to nothing"
        );
    }

    #[test]
    fn an_oversized_archive_is_refused_before_it_is_unpacked() {
        let zip = stored_zip(&[("chrome-linux/big", &[0u8; 4096], 0o644)]);
        let err = browser_layer(&zip, 16).expect_err("must refuse");
        assert!(err.contains("refusing"), "{err}");
    }

    #[test]
    fn something_that_is_not_a_zip_is_refused() {
        let err = browser_layer(b"definitely not a zip", 1 << 20).expect_err("must refuse");
        assert!(err.contains("not a zip"), "{err}");
    }

    /// The port has to agree with itself in three places: the flag Chromium is
    /// given, the address the readiness probe asks, and [`CDP_PORT`], which is
    /// what `chm create --expose` will be told.
    ///
    /// The *address* is deliberately not asserted, and that is a measurement
    /// rather than an omission: `remote-debugging-address` does not exist in
    /// this build. Passing a flag that does nothing would be the kind of claim
    /// this project does not make.
    /// The trust store must be *assembled*, not merely installed. The package
    /// ships the parts and builds the bundle in a maintainer script that never
    /// runs here, so without this every TLS client in the guest fails in a way
    /// that reads as a network fault.
    #[test]
    fn the_ca_bundle_is_built_from_the_certificates_that_were_installed() {
        let mut r = Rootfs::new();
        for (p, body) in [
            ("usr/share/ca-certificates/mozilla/One.crt", "-----A-----\n"),
            ("usr/share/ca-certificates/mozilla/Two.crt", "-----B-----"),
            ("usr/share/ca-certificates/mozilla/README", "not a cert"),
        ] {
            r.insert(
                p.to_string(),
                EntryKind::File {
                    mode: 0o644,
                    size: body.len() as u64,
                },
                body.as_bytes().to_vec(),
            );
        }
        install(&mut r);
        let bundle = r.get(CA_BUNDLE).expect("no trust store was built");
        let text = String::from_utf8(bundle.data.clone()).unwrap();
        assert!(text.contains("-----A-----"), "{text}");
        assert!(text.contains("-----B-----"), "{text}");
        assert!(!text.contains("not a cert"), "{text}");
        assert!(
            text.ends_with('\n'),
            "a bundle whose last certificate has no trailing newline runs \
             into whatever is appended next: {text:?}"
        );
    }

    /// An image with no `ca-certificates` must not gain an empty bundle: an
    /// empty trust store is worse than an absent one, because a client that
    /// finds the file stops looking anywhere else and every connection fails
    /// with an error that blames the wrong thing.
    #[test]
    fn no_certificates_means_no_bundle_rather_than_an_empty_one() {
        let mut r = Rootfs::new();
        install(&mut r);
        assert!(
            r.get(CA_BUNDLE).is_none(),
            "an empty trust store was written"
        );
    }

    #[test]
    fn the_launch_script_serves_cdp_on_the_port_it_documents() {
        let s = launch_script();
        assert!(
            s.contains(&format!("--remote-debugging-port={CDP_PORT}")),
            "the browser is not told which port to serve:\n{s}"
        );
        assert!(
            s.contains(&format!("http://127.0.0.1:{CDP_PORT}/json/version")),
            "the readiness probe asks a different port from the one the \
             browser serves, so it can never succeed:\n{s}"
        );
        assert!(
            !s.lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .any(|l| l.contains("remote-debugging-address")),
            "this build has no such switch (measured: `strings` lists only \
             remote-debugging-port and remote-debugging-pipe), so passing it \
             asserts something untrue:\n{s}"
        );
    }

    #[test]
    fn the_launch_script_mounts_dev_shm() {
        let s = launch_script();
        assert!(
            s.contains("mount -t tmpfs tmpfs /dev/shm"),
            "the generated init does not mount /dev/shm and Chromium needs \
             it:\n{s}"
        );
        assert!(
            !s.contains("size=64m"),
            "sizing /dev/shm at the container default is the bug \
             --disable-dev-shm-usage exists to work around:\n{s}"
        );
    }

    /// The sandbox branch is the one that is easy to lose in an edit, because
    /// `--no-sandbox` alone works and looks fine.
    #[test]
    fn the_sandboxed_path_is_tried_before_the_root_path() {
        let s = launch_script();
        let probe = s.find("unshare --user").expect("no user-namespace probe");
        let sandboxed = s.find("setpriv --reuid").expect("no privilege drop");
        let fallback = s.find("--no-sandbox").expect("no fallback");
        assert!(
            probe < sandboxed && sandboxed < fallback,
            "the unprivileged path must be attempted first, or the image \
             always runs the browser as root:\n{s}"
        );
        assert!(
            s.contains(&format!("--reuid={RUN_UID}")),
            "the uid must come from RUN_UID, not be restated:\n{s}"
        );
    }

    /// The entrypoint is interpolated into the generated init unquoted, so a
    /// path with a shell metacharacter in it would change how the init parses.
    #[test]
    fn the_entrypoint_path_needs_no_quoting() {
        assert!(
            LAUNCH_PATH
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
            "`{LAUNCH_PATH}` is interpolated into the init unquoted"
        );
        assert!(
            LAUNCH_PATH.starts_with(GUEST_DIR),
            "the launcher must live with the browser it launches"
        );
    }

    /// The subtraction is the security argument. If the package manager
    /// survives, "a browser and nothing else" is false.
    #[test]
    fn the_package_manager_is_on_the_removal_list() {
        for needed in ["usr/bin/apt", "usr/bin/dpkg", "var/lib/dpkg", "etc/apt"] {
            assert!(
                REMOVED.iter().any(|(p, _)| *p == needed),
                "`{needed}` is not removed, so the guest is more than a browser"
            );
        }
        for (path, why) in REMOVED {
            assert!(!path.starts_with('/'), "`{path}` must be rootfs-relative");
            assert!(!why.is_empty(), "`{path}` is removed for no stated reason");
        }
    }

    /// A rootfs holding the package-manager binaries `ubuntu:24.04` arm64
    /// actually ships, enumerated from its own layer rather than imagined.
    fn ubuntu_package_tools() -> Rootfs {
        let mut r = Rootfs::new();
        for p in [
            "usr/bin/apt",
            "usr/bin/apt-cache",
            "usr/bin/apt-cdrom",
            "usr/bin/apt-config",
            "usr/bin/apt-get",
            "usr/bin/apt-key",
            "usr/bin/apt-mark",
            "usr/bin/dpkg",
            "usr/bin/dpkg-deb",
            "usr/bin/dpkg-divert",
            "usr/bin/dpkg-maintscript-helper",
            "usr/bin/dpkg-query",
            "usr/bin/dpkg-realpath",
            "usr/bin/dpkg-split",
            "usr/bin/dpkg-statoverride",
            "usr/bin/dpkg-trigger",
            "usr/sbin/dpkg-preconfigure",
            "usr/sbin/dpkg-reconfigure",
            "usr/bin/debconf",
            "usr/bin/debconf-apt-progress",
            "usr/bin/debconf-communicate",
            "usr/bin/debconf-copydb",
            "usr/bin/debconf-escape",
            "usr/bin/debconf-set-selections",
            "usr/bin/debconf-show",
            "var/lib/dpkg/status",
            "etc/apt/sources.list",
        ] {
            r.insert(
                p.to_string(),
                EntryKind::File {
                    mode: 0o755,
                    size: 4,
                },
                b"elf\n".to_vec(),
            );
        }
        r
    }

    /// The removal list is measured against a real base image's contents, not
    /// against itself. `usr/bin/apt` is not a prefix of `usr/bin/apt-get`
    /// under this matcher, so an under-specified list leaves the tool that
    /// installs software sitting in the guest.
    #[test]
    fn every_package_tool_ubuntu_ships_is_actually_removed() {
        let mut r = ubuntu_package_tools();
        strip(&mut r);
        let left: Vec<&str> = r.paths().collect();
        assert!(
            left.is_empty(),
            "these package-manager paths survived strip(): {left:?}"
        );
    }

    /// The independent check. `audit` must not merely agree with `REMOVED` --
    /// it has to notice a tool nobody wrote down.
    #[test]
    fn the_audit_catches_a_package_tool_the_removal_list_never_named() {
        let mut r = ubuntu_package_tools();
        r.insert(
            "usr/bin/apt-tomorrow".to_string(),
            EntryKind::File {
                mode: 0o755,
                size: 4,
            },
            b"elf\n".to_vec(),
        );
        strip(&mut r);
        let found = audit(&r);
        assert_eq!(
            found.len(),
            1,
            "audit should have caught exactly the unlisted tool, got {found:?}"
        );
        assert!(found[0].starts_with("usr/bin/apt-tomorrow: "));
    }

    /// A remote shell is the one addition that would dissolve the security
    /// argument entirely, so it is named explicitly rather than left to the
    /// package-manager rules to catch by luck.
    #[test]
    fn the_audit_refuses_a_remote_shell() {
        let mut r = Rootfs::new();
        r.insert(
            "usr/sbin/sshd".to_string(),
            EntryKind::File {
                mode: 0o755,
                size: 4,
            },
            b"elf\n".to_vec(),
        );
        assert_eq!(audit(&r).len(), 1, "an sshd in the guest went unnoticed");
    }

    /// The audit asks about executables, so it must not fire on a library or a
    /// stray data file that merely has the word in its name. A check that
    /// cries wolf gets disabled, and then guards nothing.
    #[test]
    fn the_audit_ignores_libraries_and_data_that_merely_share_a_name() {
        let mut r = Rootfs::new();
        for p in [
            "usr/lib/aarch64-linux-gnu/libapt-pkg.so.6.0",
            "usr/share/doc/apt/README",
            "opt/gimbal-browser/headless_shell",
            "usr/bin/aptitude-create-state-bundle",
            // Named exactly like the tools, and deliberately not in a
            // directory anything is run from: if the audit stopped asking
            // *where* a thing is, these would be reported as surviving
            // package managers and the check would start crying wolf.
            "var/cache/apt",
            "etc/dpkg",
            "var/cache/debconf",
        ] {
            r.insert(
                p.to_string(),
                EntryKind::File {
                    mode: 0o755,
                    size: 1,
                },
                b"x".to_vec(),
            );
        }
        assert!(
            audit(&r).is_empty(),
            "the audit fired on inert content: {:?}",
            audit(&r)
        );
    }

    /// `/etc/passwd` is appended to, never replaced. Replacing it would take
    /// `root` with it, and the generated init runs as root before the launch
    /// script drops privilege -- so the guest would fail in a way that looks
    /// nothing like its cause.
    #[test]
    fn installing_the_browser_user_keeps_the_users_the_image_already_had() {
        let mut r = Rootfs::new();
        r.insert(
            "etc/passwd".to_string(),
            EntryKind::File {
                mode: 0o644,
                size: 0,
            },
            b"root:x:0:0:root:/root:/bin/bash\n".to_vec(),
        );
        install(&mut r);
        let passwd = String::from_utf8(r.get("etc/passwd").unwrap().data.clone()).unwrap();
        assert!(passwd.contains("root:x:0:0:"), "root was lost: {passwd}");
        assert!(passwd.contains(&format!(":{RUN_UID}:{RUN_UID}:")));
    }

    /// The launcher is written straight into the rootfs rather than shipped as
    /// a layer, so no image content can shadow the one file the guest boots
    /// into. If it were not executable the guest would panic at `exec`.
    #[test]
    fn the_launcher_is_installed_executable_at_the_entrypoint_path() {
        let mut r = Rootfs::new();
        install(&mut r);
        match r.get(LAUNCH_PATH).expect("no launcher was installed").kind {
            EntryKind::File { mode, .. } => assert_eq!(
                mode & 0o111,
                0o111,
                "the launcher is not executable, so the guest cannot exec it"
            ),
            ref other => panic!("the launcher is not a file: {other:?}"),
        }
    }

    /// The base is not a free choice: `strip` and the pinned library set were
    /// both measured against this release, and its `.deb`s are the zstd ones
    /// chm can already read.
    #[test]
    fn the_default_base_is_the_release_the_libraries_were_pinned_from() {
        assert_eq!(BASE_IMAGE, "ubuntu:24.04");
        assert!(
            RUNTIME_DEBS
                .iter()
                .all(|p| p.url().starts_with(UBUNTU_POOL)),
            "a library is pinned outside the pool the base image comes from"
        );
    }

    /// Every read from a socket in the launcher must be bounded. Chrome's
    /// DevTools HTTP endpoint does not close on `Connection: close`, so an
    /// unbounded read hangs forever -- it cost this project 1h49m once, and
    /// this is the guard that stops it costing it twice.
    ///
    /// The `/dev/tcp` half is not paranoia either: Microsoft Defender
    /// quarantines files containing that idiom as `SuspiciousPosixRevShell`
    /// and zeroes them on write, so a launcher carrying it could arrive in the
    /// guest empty.
    #[test]
    fn every_probe_the_launcher_makes_is_bounded_in_time() {
        let script = launch_script();
        assert!(
            !script.contains("/dev/tcp"),
            "the launcher uses the /dev/tcp idiom, which endpoint scanners \
             quarantine and which has no timeout"
        );
        for line in script.lines().filter(|l| l.contains("curl")) {
            assert!(
                line.contains("--max-time"),
                "an unbounded curl would hang the guest forever: {line}"
            );
        }
        assert!(
            script.contains("curl"),
            "the launcher no longer probes CDP at all, so it can never report \
             readiness"
        );
    }

    /// A caller has to be able to stop waiting. "Slow" and "dead" look
    /// identical until the guest says which it is, so both outcomes are
    /// reported and the markers cannot be confused for one another.
    #[test]
    fn the_launcher_reports_failure_as_clearly_as_success() {
        let script = launch_script();
        assert!(
            script.contains(READY_MARKER),
            "nothing announces readiness, so a client can only guess"
        );
        assert!(
            script.contains(FAILED_MARKER),
            "a guest whose browser died would look identical to a slow one"
        );
        assert!(
            !READY_MARKER.contains(FAILED_MARKER) && !FAILED_MARKER.contains(READY_MARKER),
            "one marker is a substring of the other, so matching on either \
             matches both"
        );
        assert!(
            script.contains(&format!("[ $i -lt {READY_DEADLINE_SECS} ]")),
            "the wait is not bounded by READY_DEADLINE_SECS, so a browser \
             that never starts hangs the boot"
        );
    }

    #[test]
    fn the_browser_pin_names_the_revision_it_documents() {
        assert!(
            BROWSER_URL.contains(&format!("/chromium/{BROWSER_REVISION}/")),
            "the URL and BROWSER_REVISION disagree: {BROWSER_URL}"
        );
        assert!(
            BROWSER_URL.contains("chromium-headless-shell-linux-arm64"),
            "this must be the headless shell, arm64: {BROWSER_URL}"
        );
    }
}
