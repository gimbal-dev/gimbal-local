# `chm exec` — run a command in the sandbox and get its exit status

Before this existed, the only way to make a guest do something from a script was
`chm ctl input`, which types characters at a serial console. It has no notion of
a command: no exit status, no boundary around the output, and no way to tell
*failed* from *not finished yet*. Every caller ended up scraping the console for
a substring and hoping — including our own end-to-end tests, which is how we
knew the shape was wrong.

```console
$ chm exec -- uname -a
Linux ch-snap 6.8.0-136-generic #136-Ubuntu SMP PREEMPT_DYNAMIC aarch64 GNU/Linux
$ echo $?
0

$ chm exec -- sh -c 'exit 42'
$ echo $?
42
```

## Using it

```
chm exec [--socket PATH] [--timeout SECS] [--json] -- <command> [args...]
```

It runs against the guest that `chm serve` currently has running, so the
sequence is `chm serve <library>` → `chm ctl start <name>` → `chm exec`. The
guest must be sitting at a shell prompt; if it is at a login prompt instead, the
command is typed into the username field and the exec times out (see
[Failure modes](#failure-modes)).

| Flag | Meaning |
| --- | --- |
| `--timeout SECS` | Give up waiting after `SECS`. Default 300. |
| `--json` | Print `{status, exit_code, output, error, duration_ms}`. |
| `--socket PATH` | Daemon socket, if not the default. |

### The arguments are an argv, not a command line

Nothing after `--` is interpreted as shell syntax. Each argument is
single-quoted before it reaches the guest, so metacharacters arrive as data:

```console
$ chm exec -- echo 'a; touch /tmp/PWNED' '$(id)' '`id`'
a; touch /tmp/PWNED $(id) `id`
$ chm exec -- ls /tmp/PWNED
ls: cannot access '/tmp/PWNED': No such file or directory
```

When you *want* a shell — a pipeline, a redirect, a glob — ask for one:

```console
$ chm exec -- bash -lc 'make build 2>&1 | tail -20'
```

That is deliberate. A command surface that runs a shell only when it spots a
metacharacter is one where the security properties of a call depend on the
contents of its own arguments, and callers cannot reason about that.

## Exit status

The guest command's exit status becomes `chm exec`'s, so `chm exec -- make` fails
your script exactly when `make` fails.

**A transport failure never reports success.** If we cannot obtain a verdict, we
say so rather than defaulting to zero:

| Exit | Meaning |
| --- | --- |
| `0`–`123`, `126`–`255` | The guest command's own status. |
| `124` | The guest did not report completion before the timeout. |
| `125` | `chm` could not run the command at all. |

`124` and `125` are conventional (`timeout(1)` and `env(1)` use them), but a
guest command *can* legitimately exit with those values, so the exit status is a
convenience and **`--json` is the contract**:

```console
$ chm exec --timeout 3 --json -- sleep 30
{"status":"timeout","exit_code":null,"output":"","error":"the guest did not report completion …","duration_ms":3025}
```

`exit_code` is non-null **only** when `status` is `completed`. Any consumer that
branches on `status` first cannot mistake a timeout for a successful command.

## Failure modes

| `status` | What happened | What to do |
| --- | --- | --- |
| `timeout` | No completion marker in time. The command may still be running — or the guest may not be at a shell prompt. | `chm ctl console` to see where the guest actually is. Raise `--timeout`. |
| `overflowed` | More than 128 KiB of output without finishing. | Redirect to a file in the guest and copy it out. |
| `truncated` | The daemon's console ring evicted our output before we could read it. | Another writer is flooding the console; quieten it or capture less. |
| `error` | No VM running, the guest stopped mid-command, another exec is already in flight, or the command was too long. | The `error` field says which. |

Only one exec runs at a time. Two commands typed into one console interleave
their characters and both come back wrong, so a second caller is **refused**
rather than queued — a stuck exec cannot silently stall everything behind it.

## How it works, and what that costs you

The transport is the guest's serial console. A guest agent over vsock would give
real streams and process identity, but it needs software *inside* the guest,
which would restrict this to images we build. The console is the one channel
every image already has, including a bring-your-own image we have never seen.

For each exec we mint a random nonce `N` and send:

```sh
printf '%s%s\n' 'N' 'BEG'; { <quoted argv> ; } 2>&1; __chm_rc=$?; printf '%s%s:%d\n' 'N' 'END' "$__chm_rc"
```

The shell **echoes that line back** before running it, so the console holds the
marker text twice. The two are told apart structurally rather than by guessing:
the echo contains `N` and `BEG` as separate `printf` arguments and never their
concatenation, while the executed `printf` emits `NBEG` joined. We match the
joined form, so the echo cannot match. Here is a real transcript:

```
ubuntu@ch-snap:~$ <'%s%s:%d\n' 'chm590c60dce824c9f4' 'END' "$__chm_rc"   <- the echo: separate words
chm590c60dce824c9f4BEG                                                  <- the output: joined
marker-probe
chm590c60dce824c9f4END:0
ubuntu@ch-snap:~$
```

The nonce is minted per exec from the system CSPRNG, so console text written
*before* the request — including the tail of a previous exec that timed out —
cannot match this one's end marker.

### The limits this transport imposes

These are properties of the console, not of the interface. A future vsock
transport can remove them without changing the command surface.

- **stdout and stderr are combined.** They are one wire.
- **Output is console text, not a byte-exact stream.** The terminal has already
  cooked it. We rewrite the tty's `CRLF` back to `LF` (a lone `CR` is left
  alone, since that is a program redrawing a line), but binary output will not
  survive. Write it to a file in the guest instead.
- **Commands are capped at 4000 bytes** of framed input. A Linux tty in
  canonical mode silently discards everything past `N_TTY_BUF_SIZE` (4096), so
  an over-long command would arrive mangled and then time out with no
  explanation. We refuse it up front instead. Put it in a script and run that.
- **Output is capped at 128 KiB** per exec, well below the daemon's 256 KiB
  console ring, so a large-output command is reported as `overflowed` rather
  than silently clipped by eviction.

### What a hostile guest can do

It can lie about the exit status — it is the thing running the command, so no
transport changes that. What it must not be able to do is make a *transport*
failure look like success, and that is the property this design protects: a
missing or malformed end marker is never reported as `completed`.
