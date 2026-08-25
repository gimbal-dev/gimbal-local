# The browser sandbox

A guest that is a browser and nothing else. An agent drives it over the Chrome
DevTools Protocol from the host, and has no other way in or out.

This is the first workload built *on* this stack rather than into it: it uses
the OCI image path, the userspace NAT and the ingress mapping without adding
anything hypervisor-side.

---

## Build one

```console
$ chm image build --browser --kernel ~/gimbal-images/ubuntu/Image --out ~/gimbal-images/browser
```

That produces an arm64 rootfs holding `chromium-headless-shell`, the shared
libraries it links against, and **no package manager**. The guest boots straight
into the browser, which listens for CDP on port **9222**.

The browser comes from the Playwright CDN rather than from a distribution
package. Ubuntu supplies only libraries; its own `chromium-browser` package is a
snap shim that cannot work in a container.

Why `chromium-headless-shell` and not something smaller, measured for #329 on
arm64:

| Build | Download | Playwright native deps |
| --- | --- | --- |
| chromium (full) | 165.1 MB | 22 |
| **chromium-headless-shell** | **103.0 MB** | **22** |
| firefox | 85.8 MB | 27 |
| webkit | 84.6 MB | 57 |

WebKit has the smallest download and by far the largest dependency closure, so
choosing on download size picks the wrong engine — and neither Firefox nor
WebKit speaks CDP. Google's chrome-for-testing publishes no linux-arm64 build at
all, which is the single reason the upstream `kernel/kernel-images` approach
cannot be reused as-is on Apple Silicon.

---

## Run one, and reach it

```console
$ chm create \
    --kernel ~/gimbal-images/browser/Image \
    --disk   ~/gimbal-images/browser/rootfs.img \
    --cpus 2 --memory 2048 \
    --net \
    --expose 9222 \
    --egress-allow example.com:443 \
    --workspace /tmp/browser-workspace
```

`--expose 9222` is what makes CDP reachable. The host port is **chosen by the
OS**, not assumed, and announced on the console:

```
chm: ingress 127.0.0.1:<HOST_PORT> -> guest <GUEST_IP>:9222
```

Read the port back from that line rather than hard-coding one. The listener is
**loopback-only**, so exposing a browser does not publish it to the LAN.

Then connect from the host with `playwright-core`. No browser download is
needed on the Mac — the browser is in the VM:

```console
$ npm i playwright-core
```

```js
import { chromium } from 'playwright-core';
const browser = await chromium.connectOverCDP(`http://127.0.0.1:${HOST_PORT}`);
const page = await browser.newPage();
await page.goto('https://example.com');
```

---

## What the isolation actually is

`--egress-allow` is an allow-list and egress is **default-deny**: a destination
outside the policy is refused, and the refusal is written to the console naming
the governing policy, so a blocked navigation is distinguishable from a broken
one.

Deliberately absent from the image: a shell server, an exec endpoint, an sshd.
Upstream `kernel/kernel-images` ships `/process/exec` and `/process/spawn` in
its equivalent image; that is precisely the part not reused.

The security argument for exposing a raw CDP port at all is that the blast
radius is a VM whose entire contents are a browser. That argument is doing real
work, because **raw CDP can read `file://` and write downloads**.

No credential-injection rule should be attached to a browser sandbox. A browser
that can be steered to an injection host would make authenticated requests on
the agent's behalf — right for a coding agent, wrong for a browser sandbox.

---

## The sandbox-inside-the-sandbox, and when it weakens

Chromium's own sandbox needs an unprivileged user namespace. Whether the kernel
grants one is a property of *the kernel*, not of the image, so the generated
init measures it at boot rather than deciding at build time:

- **User namespaces work** → the browser drops to an unprivileged uid and runs
  sandboxed. The console says so.
- **They do not** → Chromium refuses to start with a sandbox at all, and the
  init runs it as root, saying so on the console and naming the remedy.

The usual cause is not a missing kernel feature. Ubuntu 24.04 ships
`kernel.apparmor_restrict_unprivileged_userns=1`, which denies the syscall to
unconfined processes. A **rehydrated cloud capture carries that setting in from
the cloud host**; a container rootfs built here carries no AppArmor policy and
so never hits it.

The VM remains the security boundary either way, but this is the weaker of the
two paths and the console says which one is in force rather than passing
`--no-sandbox` quietly.

`chm posture` does **not** currently report this setting
([#363](https://github.com/gimbal-dev/gimbal-local/issues/363)): posture covers
what chm does to a guest, not what the guest can do.

---

## The acceptance gate

`scripts/hvf/browser-sandbox-acceptance.sh` is the gate for the claim above. It
runs four checks, and the last three are what make the first mean anything:

| | Check | What it proves |
| --- | --- | --- |
| **A** | Happy path | Playwright `connectOverCDP` renders, evaluates, screenshots, and loads an allow-listed page off the real internet |
| **B** | Ingress | The only way in is the exposed port — the guest's own address is *not* reachable from the host, so access comes from the ingress mapping and not from host routing |
| **C** | Egress | A destination outside the profile is refused, the browser sees a navigation error rather than a blank page, and the refusal names the governing policy |
| **D** | No creds | No credential-injection rule is in play |

```console
$ scripts/hvf/browser-sandbox-acceptance.sh [IMAGE_DIR]
```

It needs a signed `chm` (`scripts/build-chm.sh`) and `playwright-core` on the
host. `IMAGE_DIR` defaults to `$CHM_BROWSER_IMAGE`, then
`~/gimbal-images/browser`.

Check B is the one worth understanding: proving you can reach the browser is
easy, and means nothing on its own. Proving the guest is reachable *only*
through the mapping is what turns it into an isolation claim.

---

## Known limits

- A browser guest can be warm-resumable **or** keep its own sandbox, but not
  both ([#361](https://github.com/gimbal-dev/gimbal-local/issues/361)).
- `chm posture` cannot see the guest-side setting that decides whether the
  in-guest sandbox is available
  ([#363](https://github.com/gimbal-dev/gimbal-local/issues/363)).

---

## Where the code lives

| Path | What it is |
| --- | --- |
| `chm/src/oci/browser.rs` | `chm image build --browser`: the rootfs, the generated init, the CDP port constant |
| `scripts/hvf/browser-sandbox-acceptance.sh` | The four-check acceptance gate |
| `scripts/hvf/browser-cdp-drive.mjs` | The Playwright driver the gate uses |
