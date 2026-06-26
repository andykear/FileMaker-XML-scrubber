# FileMaker XML Scrubber

[![Stars](https://img.shields.io/github/stars/andykear/FileMaker-XML-scrubber?style=social)](https://github.com/andykear/FileMaker-XML-scrubber)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

A single file, browser-based tool that strips credential values from FileMaker XML before you share it with AI tools or other developers. Everything runs locally in your browser. Nothing is uploaded anywhere.

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
- **AWS** access key IDs (`AKIA`, `ASIA`)
- **GitHub** tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- **Slack** tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`)
- **Stripe** keys (`sk_live_`, `rk_live_`, `sk_test_`, `rk_test_`)
- **SendGrid** API keys (`SG.xxxx.xxxx`)
- **PEM and SSH private keys** (`-----BEGIN ... PRIVATE KEY-----`), including keys split across concatenated literals
- **Incoming webhook URLs** for Slack, Discord and Microsoft Teams, where the URL itself carries the auth token

### Contextual redaction

These depend on where a value sits or what it is named, so they are matched only outside comment blocks.

- **Configure AI Account** step values (step id 212), fully redacted
- **Set Variable** steps (step id 141) whose name matches a credential keyword: a single literal is replaced whole, an expression has every literal inside it redacted
- **Inline keyword assignments** inside calculations, such as `apikey = "value"`, including Let() locals with no `$` prefix
- **Credential keywords** covered: api key, token, bearer, password, secret, SMTP pass or key, private key, auth key, SSH key, SFTP pass, passphrase, credential, OAuth
- **Connection string passwords** (`password=` and `pwd=` in DSN and connection attributes)
- **Azure storage keys**: the `AccountKey=` and `SharedAccessSignature=` segments of a connection string, leaving the endpoint and account name as context
- **Plugin licence keys**: the literal arguments to `MBS("Register"; ...)` and any `*_Register(...)` activation call, with the MBS selector preserved
- **Internal hostnames and private IPs**, replaced with `[HOST]`. Public URLs are left alone
- **Attributes** whose name matches a credential keyword

---

## What it does NOT remove

This is a heuristic scrubber, not a guarantee. It does not catch:

- Account names and privilege set names
- Internal file paths and file names
- ESS and ODBC data source names beyond the password field
- Email addresses and SMTP server names
- Value list contents, schema names, field names or any sensitive literal that does not match a credential shape

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

1. Open `filemaker-xml-scrubber.html` in any modern browser
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

CC BY 4.0. See [LICENSE](LICENSE).

Provided as is, with no warranty. The tool may miss values or redact more than you expect. You are responsible for checking the output before sharing it.

---

v1.1 · [Clockwork Creative Technology](https://www.clockworkct.co.uk)
