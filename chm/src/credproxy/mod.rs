// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//
//! The credential-injecting egress proxy.
//!
//! # The problem
//!
//! A coding agent running in the sandbox needs to clone a repository, pull from
//! a registry, and call an API. Each of those is an authenticated outbound
//! request. The obvious implementation hands the sandbox a token — and then a
//! compromised or malicious step inside the sandbox can read it, keep it, and
//! use it long after the job is gone.
//!
//! # The approach
//!
//! The job never receives the credential. It makes its normal outbound call with
//! no secret at all. Because the sandbox's entire network is ours (a userspace
//! NAT, see `hypervisor::hvf::virtio::nat`), that call can be routed through a
//! host-side proxy which attaches the real credential at the moment the request
//! leaves for an allowlisted destination. The origin sees an authenticated
//! request; the guest never held the secret.
//!
//! # The split that makes this worth doing
//!
//! * **Remote-call secrets** — a forge token, a registry login, a cloud API key.
//!   Their only purpose is to authenticate an outbound request, so the guest
//!   does not need to hold them. These belong here, and the guest's copy of them
//!   drops to zero.
//! * **On-machine secrets** — a key some local tool actually invokes. The work
//!   is not a network call, so a network chokepoint cannot help. These stay in
//!   the guest and need their own protection.
//!
//! This module handles the first bucket. Naming the split is the point: it lets
//! us move as many secrets as possible out of "sitting on the runner" and into
//! "attached at transport time".
//!
//! # Module map
//!
//! * [`der`] / [`ca`] — the workspace CA and on-demand leaf minting, needed
//!   because attaching a header to an HTTPS request means terminating its TLS.
//! * [`rules`] — which destinations are intercepted, and what gets attached.
//! * [`secrets`] — where a credential comes from, including minting one per
//!   request so no standing token exists.
//! * [`http`] — request-head parsing and rewriting.
//! * [`server`] — the listener, TLS termination, verified upstream connection,
//!   and byte relay.
//!
//! `docs/credential-proxy.md` carries the design rationale and the three open
//! trades this design deliberately accepts.

pub(crate) mod base64;
pub(crate) mod ca;
pub(crate) mod cli;
pub(crate) mod der;
pub(crate) mod http;
pub(crate) mod nat;
pub(crate) mod rules;
pub(crate) mod secrets;
pub(crate) mod server;
