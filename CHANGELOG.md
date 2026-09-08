# Changelog

## 0.10.0

Integrator-visible changes:

- **`error.backtrace` is now a STRING**, frames joined with `"\n"` and still capped at
  `max_backtrace_lines`. It was a JSON array, which the rootcause host (and the wire contract:
  `rootcause-embassy/CONTRACT.md`, golden `fixtures/actions/result_action_error.json`) decodes into a
  string field — so **every action whose script raised** came back as a signed HTTP 200 the host could
  not unmarshal, settling the run as `uncertain`/`parse_result` and losing the real exception. The
  total-deadline result now carries `""` instead of `[]` for the same reason.
- Contract fixtures re-vendored from hub `9851dc4bd2017a07bdfeb9505bb3e4cd82c385f7`.

## 0.9.0

Integrator-visible changes:

- **`dry_run` must be a JSON boolean.** A non-boolean value is now refused with `400 invalid_request`
  *before* the script fetch, instead of being read as truthy. Absent still means "execute".
- **`actions[].resource_url` is validated.** A value that is not an absolute `http(s)` URL is dropped
  from the proposed action; the analysis result is still delivered. `executed_actions[]` never carries
  the field.
- **New config `max_total_attachment_bytes` (default 6 MiB).** `start_analysis` now raises before
  sending when a trigger's decoded attachments exceed the aggregate cap, matching the host's limit.
  The per-attachment `max_attachment_bytes` is unchanged.
- **A malformed API URL raises `ArgumentError`.** `Api#request` previously turned an unparseable URL
  or port into a retryable `Response`, which a background job would retry forever.
- Unexpected-exception log lines carry the exception class only, never its message text.
