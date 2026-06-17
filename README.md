# FileMaker XML Scrubber

A single file, browser based tool that strips credential values from FileMaker XML before you share it with AI tools or other developers. Everything runs locally in your browser. Nothing is uploaded.

## What problem does this solve?

When you paste FileMaker script XML or DDR exports into ChatGPT, Claude, Gemini or any other AI tool, you risk leaking API keys, passwords, OAuth tokens and internal hostnames that are embedded in your calculations and script steps. This tool scans the XML, shows you exactly what it found, and lets you download a redacted copy with the secrets replaced and the surrounding logic preserved.

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

## What it removes

- **Known key formats** in string literals: OpenAI (`sk-`, `sk-proj-`), Anthropic (`sk-ant-`), Google (`AIza`), xAI (`xai-`), Groq (`gsk_`), AWS (`AKIA`, `ASIA`), GitHub (`ghp_`, `github_pat_`), Slack (`xox`), Stripe (`sk_live_`, `rk_live_`).
- **Configure AI Account** step values (step id 212), fully redacted.
- **Set Variable** steps (step id 141) whose name matches a credential keyword. Single literals are replaced whole. Expressions have every literal inside them redacted.
- **Inline keyword assignments** like `apikey = "value"` inside calculations, including Let() locals with no `$` prefix.
- **Connection string passwords** (`password=` or `pwd=` in DSN and connection attributes).
- **Internal hostnames and private IPs**, replaced with `[HOST]`. Public URLs are left alone.
- **Attributes** whose name matches a credential keyword.

Comment blocks inside calculations are skipped. Known key formats (which have near zero false positive rates) are still caught everywhere, including inside comments.

## What it does NOT remove

This is a heuristic scrubber, not a guarantee. It does not catch:

- Account names and privilege set names.
- Internal file paths and file names.
- ESS and ODBC data source names beyond the password field.
- Email addresses and SMTP server names.
- Value list contents, schema names, field names or any sensitive literal that does not match a credential shape.

A FileMaker XML export exposes a lot of structure regardless of this tool. Always review the output before sharing it.

## Works with

- DDR XML exports
- Save as XML (full database design reports)
- Script XML (clipboard paste format, fmxmlsnippet)
- Custom function XML

UTF-8 and UTF-16 encoded files are both handled. Malformed CDATA sections (common in FileMaker exports where calculation text contains `]]>`) are automatically repaired before parsing.

## Privacy

The file is parsed, scanned and redacted entirely in the browser using the DOM. There is no network call, no upload, no analytics. You can run it offline from a local copy.

## Usage

Open `filemaker-xml-scrubber.html` in any modern browser. Drop a file or click to choose one. Review the findings. Download the redacted copy or copy it to the clipboard.

Detection settings are available behind the disclosure panel if you need to adjust which patterns are active or add your own custom keywords.

## About the output

Calculations stay inside CDATA so operators are not re-escaped into entities. If nothing matched, the original text is returned unchanged. The output is intended for sharing and review. It is not guaranteed to paste back cleanly into the FileMaker Script Workspace; work from your original for that.

## Licence

CC BY 4.0. See [LICENSE](LICENSE).

Provided as is, with no warranty. The tool may miss values or redact more than you expect. You are responsible for checking the output before sharing it.

---

v1.0 · [Clockwork Creative Technology](https://www.clockworkct.co.uk)
