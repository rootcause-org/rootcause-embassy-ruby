# Changelog

## 0.14.0

- Loader contract `?v=5` enables the hosted loader's per-message `getPageContext` callback.
- Contract fixtures re-vendored from hub `b3a9dad1c1d36f160a554a9cb1b5719aaa3caf5c`, including unsigned URL normalization cases.

## 0.13.0

- **Loader contract `?v=4`** (`Chat::LOADER_CONTRACT`): the hosted loader's persistent Turbo mode
  (one conversation across soft navigations, tokens only from a `refreshToken` hook, `data-rc-scope`
  boundary guard). Tags from `chat_widget_tag` behave as before; a persistent host builds its own tag
  from `Chat.token` + `LOADER_PATH`/`LOADER_CONTRACT`. Hub decision 23.
- Contract fixtures re-vendored from hub `2be70da93fcffcf48e3676905a36bd9d6f8579f0`.

## 0.12.1

- **Over-cap inline attachments** — an `unavailable` descriptor may declare any `size_bytes`; byte
  caps (8 MiB/file, 20 MiB total) count only descriptors carrying bytes. The host sends a file past
  them this way instead of refusing the action.

## 0.12.0

Integrator-visible changes (additive):

- **`RC_ACTION_RUN_ID`** — executing invocations may carry the host's `action_run_id`; it is exposed
  to the action script only while it runs (inherited values removed, restored after). Absent field →
  no variable; a malformed value refuses as signed `400 invalid_request`.
- **`start_analysis(context_refs:)`** — hand back at most one `{kind: "action_run", id:}` so the
  analysis can read the chat behind an action-created record. Shape is checked before sending
  (`ANALYSIS_REQUEST_INVALID`).
- **`TriggerError#status` / `#code`** — HTTP status and the host's error code (e.g.
  `CONTEXT_REF_REFUSED`, retry without `context_refs`); `nil` on transport/malformed responses.
- Trigger bodies now emit the hub golden key order (no semantic change).
- Contract fixtures re-vendored from hub `6d2c81878dc34c7d171b8f6cb38964b5e861880a`.

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
