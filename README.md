# New-ADJoiner

Interactive PowerShell script that creates a hybrid Active Directory user from a joiner form in one guided run, replacing the manual "copy from a model user" process.

Built and tested against a live hybrid AD / Entra ID environment. This is a generic version: organisation names, domains and OU details are placeholders.

## What it does

- Asks for ticket, name, job title, department, location, line manager, model user, employee number and description
- Re-prompts until each answer is valid
- Builds a unique `Firstname.Lastname` username (max 20 characters), adding `1`, `2`... on duplicates
- Copies OU, group memberships, City and State from a model user
- Skips and flags protected (AdminSDHolder) groups instead of copying them
- Shows a summary screen; **nothing is written to AD until you confirm**
- Generates a password (three words, first capitalised, then a symbol and a number, e.g. `Applegraintrain@1`) sized to the domain's minimum length
- Writes an audit line to the account's Notes field
- Suggests a licence for manual assignment (it does not assign licences)
- Supports multiple joiners per run and prints a run summary

## Requirements

- Windows PowerShell 5.1 or later on a domain-joined PC
- The ActiveDirectory module (RSAT)
- A privileged account that can create users and edit groups in the target OUs

## Usage

Always dry-run first. Every prompt and lookup runs, nothing is written:

```powershell
.\New-ADJoiner.ps1 -WhatIf
```

Then for real:

```powershell
.\New-ADJoiner.ps1 -Domain example.org -Company 'Example Ltd' -AdminAccountPrefix 'adm.'
```

| Parameter | Default | Purpose |
|---|---|---|
| `-Domain` | `contoso.com` | UPN / email suffix. Validated, so a typo can't create broken UPNs |
| `-Company` | `Contoso` | Written to the Company attribute |
| `-AdminAccountPrefix` | `adm.` | Pre-fills the privileged account name (`<prefix><you>@<domain>`) |

Edit the **Configuration** region at the top of the script to set your Office values, licence title patterns and employee number rule.

## Design decisions

- **Two identities per run.** The script runs as you, but every AD call uses the privileged credential (`-Credential`). The Notes field records you; the domain controller's security log (event 4720) records the privileged account.
- **One domain controller per run.** Discovered once with `-Writable` so a new account is immediately visible to the group and manager steps (no replication races).
- **No log file.** Who created each account lives on the account itself (Notes), plus AD's own `whenCreated` and the DC security log. A transcript would capture the on-screen password, so the script refuses to run if transcription is enforced by policy.
- **Password never stored.** Shown once, then the screen is cleared. Copy it before pressing Enter.
- **Cryptographic randomness.** `RNGCryptoServiceProvider` with rejection sampling, not `Get-Random`.
- **Fails safely.** If `New-ADUser` errors part-way, the script reports the partial account instead of carrying on.
- **Domain discovery uses the PC's own domain.** An email domain is often different from the AD DNS name; passing it to `Get-ADDomainController -DomainName` fails.

## Lessons from testing

- The domain minimum password length (15 here) was higher than the first draft's generator, so every real create failed. The script now reads the policy at start-up and sizes the password to it.
- A mistyped `=WhatIf` was accepted as the first positional parameter (`-Domain`), which would have run live with a broken UPN suffix. `-Domain` is now validated.
- A model user's groups decide the joiner's access, so the summary lists every group before you confirm.

## Known limitations

- **Licensing is manual.** Assigning licences needs Microsoft Graph and an admin-consent decision that is outside this script's scope. The suggested licence is shown in the summary.
- **Names are letters only** (no hyphens, apostrophes or accents), by design of the original spec.
- **Fine-grained password policies** are not visible to the start-up check. The first real create is the true test.
- **Cloud-only groups** (Teams / M365) are not in AD and are not copied.
- **Password strength.** About 34 bits: fine for a temporary password, weak as a permanent one. Consider forcing a change at logon if your process allows, or adding a fourth word.
- **Test accounts in a live OU** can sync to Entra. Check sync scope first and delete test accounts afterwards.
