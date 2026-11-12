# FileMaker XML Scrubber — Python CLI

A command-line port of `clockwork-scrubber.html` v1.4. It uses the same detection engine and produces the same redacted output, run from a terminal, a script, an automation tool, your editor or a FileMaker script instead of a browser. Everything runs locally. Nothing is uploaded anywhere.

The engine is the work of Andrew Kear of Clockwork Creative Technology, shared openly with the FileMaker/Claris community. This port follows the v1.4 engine pass for pass and keeps its original comments. Later releases of the browser tool are not included until the port is updated to match. For what is scrubbed and why, see [README.md](README.md). This file covers only how to run the command.

---

## Requirements

- **Python 3.13 or later.** Earlier versions of Python's XML writer escape `"` in text, so the output would no longer match the browser tool byte for byte. The script checks the version at startup and exits with a message if it is too old.
- **No dependencies.** The script uses only Python's standard library: `xml.dom.minidom`, `re`, `argparse`, `glob`, `base64` and a few others. There is no pip install, no virtual environment and no requirements file. Copy `fm_scrubber.py` anywhere and run it. It works offline.

The XML modules rely on expat, which is compiled into Python itself. It is present in the python.org installers, Homebrew, the Windows installer and normal Linux packages. Very stripped-down Linux images, such as Debian's `python3-minimal`, can leave it out. Install the full `python3` package there.

On macOS and Linux, check your version with `python3 --version`.

**On Windows**, `python3` is often not Python at all. Windows 10 and 11 install App execution aliases for `python` and `python3` that open the Microsoft Store. The python.org installer then provides `python` and the `py` launcher, but no `python3`, so `python3` can keep opening the Store even after Python is installed. Use `py -3.13` (or later, such as `py -3.14`) instead. It is the recommended form, because it picks that exact version even when several are installed. Plain `python` also works if you ticked "Add python.exe to PATH" in the installer, or added it yourself, since that puts the real interpreter ahead of the alias. You can turn the aliases off in Settings › Apps › Advanced app settings › App execution aliases. Check with `py -3.13 --version`, or the later version you installed.

The examples below use `python3`. On Windows, replace it with `py -3.13` (or later).

---

## Quick start

```
python3 fm_scrubber.py export.xml
```

The findings are printed to the terminal and `export-redacted.xml` is written next to the original. The original file is never modified unless you ask for it with `--overwrite`.

```
── scrubber-test-corpus.xml ──
3 KB  ·  72 lines
High 14   Medium 2   Values 20

[high] Credential-named element  Step[Re-Login]
    "[REDACTED]"
    <Password> element (Re-Login / Add Account / SMTP / ODBC class) set to a literal

[high] JSON credential value (traced to source)  Step[Set Variable]
    "[REDACTED]"
    Variable $pw is passed to JSONSetElement key "password" — redacted at its source assignment

[medium] Comment mentions a credential  Step[Set Variable]
    /* temp password is swordfish99 until go-live */
    A comment mentions a credential next to a value — nothing was changed, review by hand before sharing

16 findings, 20 values redacted

20 values redacted — scrubber-test-corpus-redacted.xml written
By category
  API keys               4
  Passwords              11
  Hostnames and IPs      5
```

---

## Usage

```
python3 fm_scrubber.py [--suffix S | --overwrite] [--enable ID] [--disable ID]
                       [--keyword KW] [-q] [-i] FILE_OR_PATTERN [...]
python3 fm_scrubber.py --list-patterns
```

| Option | Default | What it does |
|---|---|---|
| `FILE_OR_PATTERN ...` | required | One or more files or wildcards, such as `export.xml`, `*.xml` or `abc_*.xml`. `?` and `[...]` work too |
| `--suffix S` | `-redacted` | Added to the output name: `abc.xml` becomes `abcS.xml`. Values starting with a dash work, as in `--suffix -clean` |
| `--overwrite` | off | Writes the redacted XML over the original file. Cannot be combined with `--suffix` |
| `--enable ID` | | Turns a detection pattern on. Repeatable |
| `--disable ID` | | Turns a detection pattern off. Repeatable |
| `--keyword KW` | | Adds a custom keyword, the same as the custom keyword box in the browser tool. Up to 60 characters. Repeatable |
| `-q`, `--quiet`, `--silent` | off | Prints nothing except errors. Use the exit code to tell what happened |
| `-i`, `--interactive` | off | Opens a menu to toggle patterns and keywords before scanning |
| `--list-patterns` | | Prints every pattern ID with its current on/off state, then exits |
| `-h`, `--help` | | Prints the option summary |

A few rules:

- **Wildcards** are expanded by the script itself. Quoted patterns (`'*.xml'`) and Windows `cmd`, which does not expand them, both work. In `cmd`, write the pattern without single quotes (`abc_*.xml`), because `cmd` keeps them as part of the argument. PowerShell and Unix shells accept them.
- **Duplicates** are removed, so the same file named twice is processed once.
- **Files that already end in the suffix** are skipped when they come from a wildcard. Rerunning `*.xml` therefore does not produce `export-redacted-redacted.xml`. They are still processed if you name them explicitly.
- **`--enable` and `--disable`** are applied in the order given, on top of the defaults. An unknown ID is an error that lists the valid ones.
- **`--overwrite` on a file with nothing to redact** leaves that file untouched, byte for byte. Rewriting it would still change it, because the encoding declaration is removed and UTF-16 becomes UTF-8.
- **Nothing is ever prompted** unless you pass `-i`. The menu takes pattern numbers to toggle, `+word` to add a keyword, `-word` to remove one and Enter to finish. Quote keywords that contain spaces: `+"my key"`. It needs a terminal and refuses to start without one.

---

## Pattern IDs

The defaults match the checkboxes in the browser tool. Everything is on except the two personal data patterns.

### Known API key formats

| ID | Matches | Default |
|---|---|---|
| `skkey` | `sk-` / `sk-proj-`: OpenAI keys | on |
| `aikey` | `AIza...`: Google AI keys | on |
| `xaikey` | `xai-` / `gsk_`: xAI and Groq keys | on |
| `awskey` | `AKIA` / `ASIA`: AWS access keys | on |
| `ghkey` | `ghp_` / `github_pat_`: GitHub tokens | on |
| `slackkey` | `xoxb-` / `xoxp-`: Slack tokens | on |
| `stripekey` | `sk_live_` / `sk_test_`: Stripe live and test keys | on |
| `sgkey` | `SG.xxxx.xxxx`: SendGrid API keys | on |
| `ottokey` | `dk_` / `ak_`: OttoFMS Data and Admin API keys | on |
| `jwtkey` | `eyJ... . eyJ...`: JWT / JWS tokens | on |
| `pemkey` | `BEGIN PRIVATE KEY`: PEM and SSH private keys | on |
| `webhook` | `hooks.slack.com / ...`: Slack, Discord and Teams webhooks | on |

### Variable / attribute names

| ID | Matches | Default |
|---|---|---|
| `apikey` | `api_key` / `apikey`: REST API keys | on |
| `token` | `token` / `bearer`: auth tokens, JWTs | on |
| `password` | `password` / `passwd`: passwords | on |
| `secret` | `secret`: OAuth secrets, HMAC keys | on |
| `smtp` | `smtp_pass` / `smtp_key`: mail credentials | on |
| `privatekey` | `private_key` / `auth_key`: private and signing keys | on |
| `credential` | `credential` / `oauth`: OAuth credentials | on |

### Inline patterns

| ID | Matches | Default |
|---|---|---|
| `inline` | `keyword = "value"`: assigned literals | on |
| `connstr` | `password=` / `AccountKey=`: connection strings and Azure keys | on |
| `plugin` | `MBS("Register")` / `*_Register`: plugin licence keys | on |
| `curlcred` | `CURL.SetOptionPassword` and friends: SFTP/CURL credentials, traced to source | on |
| `headercred` | `Authorization:` / `Cookie:` / `-u`: HTTP header and cURL option credentials | on |
| `urlsecret` | `?api_key=` / `user:pass@`: URL query secrets and URL passwords | on |
| `urlhost` | `https://hostname/...`: internal URLs become `https://[HOST]/...` | on |
| `textnode` | `<Text>` nodes: raw string parameters in steps | on |
| `jsoncred` | `"keyword":"value"`: JSON body credentials | on |
| `nativecred` | `JSONSetElement` / `Crypt*`: positional key arguments, traced to source | on |
| `credtarget` | `<Password>` / Set Field: Re-Login, Add Account, SMTP and credential fields | on |
| `b64` | base64 `user:pass`: decoded Basic-auth literals | on |
| `commentaudit` | comment audit: flags credentials in comments, changes nothing | on |

### Personal data

| ID | Matches | Default |
|---|---|---|
| `piiemail` | email addresses, replaced with `[EMAIL]` everywhere in the file | off |
| `piicard` | card numbers, replaced with `[CARD]`, Luhn checked | off |

Two groupings are inherited from the browser tool. `xaikey` covers both xAI and Groq keys, and `connstr` also controls the Azure `AccountKey=` and `SharedAccessSignature=` redaction inside calculations.

---

## Examples

```
# Every export in the folder, findings printed for each
python3 fm_scrubber.py exports/*.xml

# A different suffix: export_clean.xml
python3 fm_scrubber.py --suffix _clean export.xml

# Replace the originals in place
python3 fm_scrubber.py --overwrite 'abc_*.xml'

# GDPR-clean as well as credential-clean
python3 fm_scrubber.py --enable piiemail --enable piicard export.xml

# Keep internal hostnames, add a house keyword
python3 fm_scrubber.py --disable urlhost --keyword myCompanyKey export.xml

# No output at all, just the exit code
python3 fm_scrubber.py -q exports/*.xml && echo clean

# Pick the patterns from a menu first
python3 fm_scrubber.py -i export.xml
```

---

## Where you can run it

The command needs nothing but a Python interpreter, writes its results to files and returns meaningful exit codes, so anything that can start a process can use it.

- **Terminal and shell scripts**: as in the examples above.
- **Automation and CI**: Make, cron, CI pipelines, or the code steps of workflow tools wherever Python 3.13 (or later) is available. Combine `-q` with the exit code to fail a job when a file cannot be processed.
- **Editors such as VS Code**: add a task that scrubs the file you are looking at. In `.vscode/tasks.json`:

  ```json
  {
    "version": "2.0.0",
    "tasks": [
      {
        "label": "Scrub current FileMaker XML",
        "type": "process",
        "command": "python3",
        "args": ["${workspaceFolder}/fm_scrubber.py", "${file}"],
        "problemMatcher": []
      }
    ]
  }
  ```

  On Windows, set `"command"` to `"py"` and put `"-3.13"` (or later) first in `"args"`, or use `"python"` if it is on your PATH.

- **FileMaker, through a plugin that can run system commands**, such as the [BaseElements plugin](https://github.com/GoyaPtyLtd/BaseElements-Plugin) with `BE_ExecuteSystemCommand ( command ; { timeout ; executeUsingShell } )`. Any other plugin that can run a shell command works the same way. `BE_ExecuteSystemCommand` returns only what the command prints to stdout, not its exit code. Run quietly and turn the exit code into text yourself:

  ```
  Set Variable [ $cmd ; Value:
      Quote ( "/opt/homebrew/bin/python3" ) & " " &
      Quote ( "/Users/Shared/Tools/fm_scrubber.py" ) & " -q " &
      Quote ( $xmlPosixPath ) & " && echo ok || echo failed" ]
  Set Variable [ $result ; Value: Trim ( BE_ExecuteSystemCommand ( $cmd ; 120000 ) ) ]
  If [ $result = "ok" ]
      # read back the file named like the original with -redacted added
  End If
  ```

  Things to watch:
  - **Use the full path to a Python 3.13 (or later) interpreter.**
    - On macOS, FileMaker does not inherit your shell's `PATH`, and a bare `python3` may be Apple's older 3.9.
    - On Windows, point to the real interpreter, for example `C:\Users\<you>\AppData\Local\Programs\Python\Python313\python.exe` (`Python314` and so on for later versions), or to `py.exe`. Never use the `WindowsApps` alias.
    - Relying on `PATH` works too, but FileMaker Pro only sees a change after it restarts. FileMaker Server runs as a service, so it sees only the system `PATH`, after a service restart, and a per-user Python install is invisible to it.
    - A full path behaves the same everywhere.
  - **Pass native paths.** `ConvertFromFileMakerPath ( path ; PosixPath )` converts a FileMaker path on macOS and Linux, and `WinPath` does the same on Windows. Quote every path, as above, because paths with spaces are common.
  - **Always give a timeout.** It is in milliseconds. Without one the plugin waits indefinitely, and a large DDR can take a while.
  - **Read the result back** with Read from Data File or the plugin's own file functions.
  - **On FileMaker Server**, the plugin must be enabled for server-side scripts and Python 3.13 (or later) must be installed on the server machine. FileMaker Cloud cannot run it.

---

## Output and exit codes

For each file you get:
- the size and line count;
- the High, Medium and Values counts;
- every finding, with its kind, location, a masked preview and a note;
- a summary by category, and the original against the redacted line count.

With more than one file, a run summary follows at the end. With `-q`, none of this is printed. Errors and warnings always go to stderr.

| Exit code | Meaning |
|---|---|
| `0` | Every file was processed |
| `1` | At least one file could not be read or parsed, or a name or pattern matched no file. The other files are still processed |
| `2` | Usage error, such as an unknown option, unknown pattern ID, empty suffix or no files given |

The output is written as UTF-8 without a BOM. Calculations stay inside CDATA so operators are not re-escaped into entities. If nothing matched, the original text is written back unchanged, as in the browser tool. UTF-16 input is handled, and malformed CDATA sections are repaired before parsing, using the same four passes as the browser tool.

---

## Differences from the browser tool

- **No clipboard copy.** The CLI always writes a file.
- **`]]>` inside a redacted calculation.** When a calculation that needed CDATA repair is also redacted, its text can end up containing `]]>`. The browser tool's scan stops with an error at that point. The CLI splits the section as `]]]]><![CDATA[>` and writes valid XML with the same content.
- **Parse error messages** come from Python's XML parser, so their wording differs from the browser's.

Everything else, including the findings, the counts and the redacted file, is identical. This was checked by running both engines on the same files and comparing the results.

---

## What it does NOT remove

Exactly what the browser tool does not remove. See [What it does NOT remove](README.md#what-it-does-not-remove) in the main README. A FileMaker XML export exposes a lot of structure regardless of this tool. Always review the output before sharing it.

---

## Privacy

The file is parsed, scanned and redacted on your machine. There are no network calls, no uploads and no telemetry. You can run it fully offline.

---

## Licence

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Free to use, share and adapt with attribution to the original work by Andrew Kear, Clockwork Creative Technology.

---

Provided as is, with no warranty. The tool may miss values or redact more than you expect. You are responsible for checking the output before sharing it.

---
v1.0 · Salvatore Colangelo @ [Goya Pty Ltd](https://goya.com.au)