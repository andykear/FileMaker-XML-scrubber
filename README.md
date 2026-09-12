# FileMaker XML Scrubber

[![Stars](https://img.shields.io/github/stars/andykear/FileMaker-XML-scrubber?style=social)](https://github.com/andykear/FileMaker-XML-scrubber)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

A single file, browser-based tool that strips credential values from FileMaker XML before you share it with AI tools or other developers. Everything runs locally in your browser. Nothing is uploaded anywhere.

Created by Andrew Kear of Clockwork Creative Technology and shared openly with the FileMaker/Claris community.

---

This repo title or near derivatives has been used to impersonate my project on github to deliver malware please check you are downloading from a legitimate source.
My tools are open source under CC BY 4.0, which is why you'll also see them vendored inside other builders' AI solutions or used as a canonical reference for testing, that's expected and welcome.

---

## What problem does this solve?

When you paste FileMaker script XML or DDR exports into ChatGPT, Claude, Gemini or any other AI tool, you risk leaking API keys, passwords, OAuth tokens, private keys and internal hostnames that are embedded in calculations and configurations.

This tool redacts them automatically while preserving the logic, so you can still get help.

---

## Before

```xml
<Step id="141" name="Set Variable">
  <Value><Calculation><![CDATA[
    Let([
      $apikey = "sk-proj-a8Kz9mXq4Lw2Rn5Yp7Bt3Jf6Hd0Vc1Sg";
      $endpoint = "https://fmserver.internal.corp/api/v2/sync"
    ]; $apikey & "|" & $endpoint)
  ]]></Calculation></Value>
  <Name>$authPayload</Name>
</Step>
```

## After

```xml
<Step id="141" name="Set Variable">
  <Value><Calculation><![CDATA[
    Let([
      $apikey = "[REDACTED]";
      $endpoint = "https://[HOST]/api/v2/sync"
    ]; $apikey & "|" & $endpoint)
  ]]></Calculation></Value>
  <Name>$authPayload</Name>
</Step>
```

The key and the internal hostname are gone. The Let() block, the concatenation, the variable name and the step structure are all intact. An AI tool can still read the logic and help you with it.

---

## What it scrubs

### Known key and secret formats

These have near zero false positive rates, so they are matched everywhere, including inside comments. The whole string literal is replaced.

- **OpenAI** API keys (`sk-`, `sk-proj-`)
- **Anthropic** API keys (`sk-ant-`)
- **Google** AI keys (`AIza`)
- **xAI** keys (`xai-`)
- **Groq** keys (`gsk_`)
- **AWS** access key IDs (`AKIA`, `ASIA`). Note this is the key ID, not the secret access key: a plain AWS secret has no reliable standalone shape, so it is caught only when assigned to a name containing `secret` (which `AWS_SECRET_ACCESS_KEY` and `SecretAccessKey` both do)
- **GitHub** tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- **Slack** tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`)
- **Stripe** keys (`sk_live_`, `rk_live_`, `sk_test_`, `rk_test_`)
- **SendGrid** API keys (`SG.xxxx.xxxx`)
- **OttoFMS** Data API keys (`dk_`) and Admin API keys (`ak_`). These are the FileMaker ecosystem's own long-lived credentials, passed as `Authorization: Bearer` headers or `?apiKey=` parameters, and no generic scrubber knows their shape
- **JWT / JWS tokens**: the three-segment `eyJ...` base64url shape, wherever it appears
- **PEM and SSH private keys** (`-----BEGIN ... PRIVATE KEY-----`), including keys split across concatenated literals
- **Incoming webhook URLs** for Slack, Discord and Microsoft Teams, where the URL itself carries the auth token

### Contextual redaction

These depend on where a value sits or what it is named, so they are matched only outside comment blocks.

- **Configure AI Account** step values (step id 212), fully redacted
- **Set Variable** steps (step id 141) whose name matches a credential keyword: a single literal is replaced whole, an expression has every literal inside it redacted
- **Inline keyword assignments** inside calculations, such as `apikey = "value"`, including Let() locals with no `$` prefix
- **Credential keywords** covered: api key, token, bearer, authorization, password, secret, SMTP pass or key, private key, auth key, SSH key, SFTP pass, passphrase, credential, OAuth
- **JSON body credentials**: `"password":"value"` and the escaped form `\"password\":\"value\"` inside hardcoded request bodies, using the same keyword list as assignments. The colon form is how credentials ride in Insert from URL `--data` payloads, where no equals sign ever appears
- **FileMaker's own credential-carrying steps**: Re-Login with specified credentials, Add Account, Reset Account Password, Change Password, Send Mail SMTP authentication and ODBC steps all wrap the password in a credential-named element like `<Password>`. The literal inside is redacted whole; account names are left as context. Variable and field references inside these elements are left visible, since the value lives elsewhere
- **Set Field and Insert Text into credential-named fields**: `Set Field [ Users::Password ; "temp123" ]` carries no keyword in the value, so the target field name is used as the identification, exactly like the Set Variable pass. Set Field By Name is covered when its calculated target names a credential field
- **JSONSetElement credential values**: `JSONSetElement ( $json ; "apiKey" ; "..." ; JSONString )` passes the value positionally, identified by the key name. Both the flat form and the bracketed `[key;value;type]` group form are handled, with the same literal, variable trace and field reference triage as the MBS CURL calls below
- **Encryption and HMAC key arguments**: the key argument to CryptEncrypt, CryptDecrypt, their Base64 twins and CryptAuthCode is the secret itself, at a fixed position. Same three-way handling: literals redacted in place, variables traced to their source Set Variable in the same script, field references flagged
- **Base64 user:pass literals**: a hardcoded `"Basic dXNlcjpwYXNz..."` is caught by the header pass when the Authorization prefix is present, but the bare token assigned to an innocently named variable has no keyword and no shape. Base64-looking runs inside literals are decoded, and anything that comes back as printable `user:password` is redacted. Strings that decode to JSON or XML (a lone JWT segment, an encoded payload) are excluded
- **HTTP header credentials**, wherever header text appears: `Authorization: Bearer/Basic/Token/Digest/OAuth` values, `X-API-Key` and similar key-carrying headers, and `Cookie`/`Set-Cookie` session values. This covers Insert from URL cURL options, including the escaped-quote form `-H \"Authorization: Bearer ...\"`, where the header name identifies the value as a credential regardless of its shape
- **cURL user options**: the password half of `-u`, `--user` and `--proxy-user user:password`, with the username kept as context
- **URL passwords**: `scheme://user:password@host` for any scheme (https, ftp, sftp, jdbc, postgres, mongodb and so on). The username stays, the password goes, and an internal host after the `@` still becomes `[HOST]`
- **Secret-bearing query parameters**: `?api_key=`, `?token=`, `?access_token=`, `?secret=`, `?sig=`, `?signature=`, `?sas=`, `?code=`, `?key=` and session-id parameters. The host is left alone even when public, since the parameter name marks the value as a credential. `key=` and `code=` are deliberately broad and will occasionally redact a non-secret; for a scrubber that is the right failure direction, and every hit is listed in the findings
- **Connection string credentials** (`password=`, `pwd=`, `AccessToken=`, `AuthenticationToken=` in DSN and connection attributes, plus `user:password@host` inside jdbc-style URLs in those attributes)
- **Azure storage keys**: the `AccountKey=` and `SharedAccessSignature=` segments of a connection string, leaving the endpoint and account name as context
- **Plugin licence keys**: the literal arguments to `MBS("Register"; ...)` and any `*_Register(...)` activation call, with the MBS selector preserved
- **SFTP/CURL credentials passed to MBS**, such as `MBS("CURL.SetOptionPassword"; ...)`, `CURL.SetOptionUserName`, and `CURL.SetOptionXOAuth2Bearer`. These pass a credential as a positional argument rather than `keyword = "value"`, so plain keyword matching can't see them, and a plain-word password has no shape a value-based scan would catch either. Three cases are handled:
  - a literal argument is redacted in place
  - a variable argument (the common case) is traced backward through the same script's own step list to the nearest `Set Variable` that assigned it, and the value is redacted there, at its source, not where it's used
  - a field reference (`Table::Password`) has nothing to redact, since the value lives in your data rather than this file, so it's flagged for manual review instead
  
  The trace is scoped to the current script only. A variable set by a calling script, or a global `$$variable` set elsewhere, will show up as unresolved rather than being silently missed.
- **Internal hostnames and private IPs**, replaced with `[HOST]`. Public URLs are left alone. Coverage now extends beyond http(s) to `fmnet:/`, `fmp://`, `sftp://`, `ftp://`, `smb://`, `ldap://`, `filewin://`, `filemac://` and UNC paths (`\\SERVER\share`), all of which were carrying internal hostnames straight through before
- **Home directory usernames**: `/Users/jsmith/`, `/home/jsmith/` and `C:\Users\jsmith\` identify employees by machine account name; the username becomes `[USER]` and the rest of the path is kept
- **Attributes** whose name matches a credential keyword

### Flagged but never modified

- **Credentials written in comment prose**: the keyword passes deliberately skip comments so documentation is not mangled, which left "temp password is hunter2" in a script or field comment invisible. Comments where a credential keyword sits next to a value now raise a finding for manual review. Nothing in the comment is changed

### Personal data (off by default)

Two optional patterns for anyone who needs the output GDPR-clean as well as credential-clean. Both are off by default because they redact data, not secrets, and you may want that data intact.

- **Email addresses**, replaced with `[EMAIL]`, everywhere in the file including value lists and attributes
- **Card numbers**, replaced with `[CARD]`. Digit runs of 13 to 19 are only treated as cards when they pass the Luhn check, which keeps FileMaker's own long internal ids out of the findings

---

## What it does NOT remove

This is a heuristic scrubber, not a guarantee. It does not catch:

- Account names and privilege set names
- File paths and file names, beyond internal hostnames in path schemes and usernames in home directories
- ESS and ODBC data source names beyond the password field
- Email addresses (unless the optional personal data pattern is on) and SMTP server names that look public
- Value list contents, schema names, field names or any sensitive literal that does not match a credential shape
- Credentials passed via a variable set in a *calling* script, or a global `$$variable` set elsewhere in the file. The SFTP/CURL trace only follows the current script's own steps; anything outside that is flagged as unresolved, not redacted

A FileMaker XML export exposes a lot of structure regardless of this tool. Always review the output before sharing it.

---

## Works with

- DDR XML exports
- Save as XML (full database design reports)
- Script XML (clipboard paste format, fmxmlsnippet)
- Custom function XML

UTF-8 and UTF-16 encoded files are both handled. Malformed CDATA sections (common in FileMaker exports where calculation text contains `]]>`) are automatically repaired before parsing.

---

## Privacy

The file is parsed, scanned and redacted entirely in the browser using the DOM. There is no network call, no upload, no analytics. You can run it offline from a local copy.

---

## Usage

1. Open `clockwork-scrubber.html` in any modern browser
2. Drop a file or click to choose one
3. Review the findings
4. Download the redacted copy or copy it to the clipboard

Detection settings are available behind the disclosure panel if you need to adjust which patterns are active or add your own custom keywords.

---

## About the output

Calculations stay inside CDATA so operators are not re-escaped into entities. If nothing matched, the original text is returned unchanged. The output is intended for sharing and review. It is not guaranteed to be 100% safe, so always review before posting.

---

## Companion tools

[FileMaker XML Inspector](https://github.com/andykear/FileMaker-XML-inspector-open-source) — analyse your FileMaker XML exports

[FileMaker Script XML Skill](https://github.com/andykear/FileMaker-XMLsnippet-Claude-Skill) — generate paste-ready script XML with Claude

[FileMaker Layout XML Skill](https://github.com/andykear/FileMaker-XMLsnippet-Layout-Claude-Skill) — generate paste-ready layout XML with Claude

[FileMaker Field Definitions XML Skill](https://github.com/andykear/FileMaker-XML-field-definitions) — generate paste-ready field definitions with Claude

---

## Licence

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to use, share, and adapt with attribution.

---

Provided as is, with no warranty. The tool may miss values or redact more than you expect. You are responsible for checking the output before sharing it.

---

v1.4 · [Clockwork Creative Technology](https://www.clockworkct.co.uk)
