# What a release depends on that is not in this repository

`scripts/release-macos.sh` builds, signs, notarizes and staples a shippable
`.app`. Everything it needs that lives *outside* the repository is written down
here, because that is the part that is lost when a laptop dies.

Every fact below was measured on 2026-08-24 with the command shown beside it.
Re-run them rather than trusting the page: a certificate expires, and a page
that is merely remembered expires with it.

## The signing identity

```console
$ security find-identity -v -p codesigning
  2) 99C85528842CA7A641441D8F15B1574555FEFDDF "Developer ID Application: Benjamin De St Paer-Gotch (89N7ZG42ZM)"
```

| fact | value |
| --- | --- |
| Apple Developer team ID | `89N7ZG42ZM` |
| Identity string for `GIMBAL_SIGN_IDENTITY` | `Developer ID Application: Benjamin De St Paer-Gotch (89N7ZG42ZM)` |
| Certificate SHA-1 | `99C85528842CA7A641441D8F15B1574555FEFDDF` |
| Issuer | Apple's `Developer ID Certification Authority` |

The team ID is not a secret: it is embedded in every artifact we publish and
`codesign -dvvv` prints it from any downloaded build.

The Apple ID that holds the membership is deliberately **not** written here.
It is not present in any shipped artifact, so recording it in a public
repository would disclose something publishing does not already disclose. Find
it locally with `xcrun notarytool history --keychain-profile gimbal-notary`,
which fails without it.

## The certificate expires 2027-02-01, and the release script says so first

```console
$ security find-certificate -c "Developer ID Application" -p \
    | openssl x509 -noout -dates
notBefore=Aug  6 12:18:54 2026 GMT
notAfter=Feb  1 22:12:15 2027 GMT
```

That is **161 days** of runway from the date this page was written, out of a
total validity of about 179 -- the certificate is only issued for six months,
which is short enough that a window measured in weeks would spend nearly all of
its life silent.

`release-macos.sh` now reads that date out of the keychain in preflight and
warns from **45** days out, then refuses once it has passed. It reads the live
certificate rather than the number above, so this page can go stale without the
warning going wrong. The window is deliberately generous: Apple usually issues a
replacement the same day, but the account-level problems that block one -- a
lapsed membership, an unaccepted agreement -- are not same-day, and a false
alarm costs one yellow line where a miss costs a blocked release.

The expiry is a **deadline, not a recall**. Builds already published keep
working, and that is a measured property rather than an assumption: signing uses
a secure timestamp from Apple's timestamp authority, so Gatekeeper can still
establish that the signature was made while the certificate was valid.

```console
$ codesign -dvvv /Applications/GimbalLocal.app
Authority=Developer ID Application: Benjamin De St Paer-Gotch (89N7ZG42ZM)
Timestamp=6 Aug 2026 at 15:22:36
$ xcrun stapler validate /Applications/GimbalLocal.app
The validate action worked!
```

So an expiry is not a recall. It stops the *next* release, including a security
fix, which is the reason it is worth knowing about before it happens rather
than after.

## Notarization, and a trap that makes it look unrepeatable

`release-macos.sh` notarizes through `xcrun notarytool` using a stored keychain
profile named by `GIMBAL_NOTARY_PROFILE`, which defaults to `gimbal-notary`.

**`security find-generic-password` cannot see that credential.** `notarytool`
stores it in the data protection keychain, which the `security` command-line
tool does not search, so every plausible service name returns *"The specified
item could not be found"* on a machine where notarization demonstrably works.
Reading that as "the credential is gone" is wrong, and it is the sort of wrong
that leads to re-issuing credentials that were never lost.

The authoritative check is the one the script itself makes:

```console
$ xcrun notarytool history --keychain-profile gimbal-notary
Successfully received submission history.
```

If that fails, recreate the profile with an app-specific password generated at
appleid.apple.com:

```console
$ xcrun notarytool store-credentials gimbal-notary \
    --apple-id <apple-id> --team-id 89N7ZG42ZM --password <app-specific-password>
```

Re-running a release therefore needs: the Developer ID certificate **and its
private key** in the login keychain, an Apple ID on the team with rights to
notarize, and an app-specific password. A machine with the certificate but no
notary profile gets all the way through building and signing before failing.

## There is no update channel

```console
$ gh api repos/gimbal-dev/gimbal-local/releases \
    --jq '.[] | .tag_name as $t | .assets[] | [$t, .download_count] | @tsv'
```

| release | downloads |
| --- | --- |
| v0.2.2 | 3 |
| v0.2.1 | 6 |
| v0.2.0 | 2 |
| v0.1.1 | 5 |
| v0.1.0 | 1 |

The app has no update check, so **14 of 17 downloads are of a version that has
since been superseded** and none of those users can learn that from the app.
This is the concrete cost of the gap, not a hypothetical one: it is the reason
a security fix currently has no route to anybody who already has a build.

Tracked as [#391](https://github.com/gimbal-dev/gimbal-local/issues/391).
