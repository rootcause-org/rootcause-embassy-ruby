# rootcause-action-runner

A **thin Ruby gem** the customer mounts once in their Rails app — the first **action runner** in
rootcause's **action plane**. It receives a signed, digest-pinned **invocation** from the rootcause
host, **resolves the action's script by digest**, runs it **inline with a hard timeout**, and returns
a **signed structured result**. No executable code ever travels on the wire.

> The authoritative design is [SPEC.md](SPEC.md). The whole-plane design (host side: registry,
> signer, confirm/execute pages, audit) lives in
> [`rootcause-light/docs/action-plane-spec.md`](https://github.com/rootcause-org/rootcause-light/blob/main/docs/action-plane-spec.md).

## Install

```ruby
# Gemfile
gem "rootcause-action-runner"
```

## Configure

```ruby
# config/initializers/rootcause.rb
RootCause::ActionRunner.configure do |c|
  c.secret    = ENV.fetch("ROOTCAUSE_ACTION_SECRET") # reverse-channel HMAC secret (per project)
  c.fetch_url = "https://<rootcause>/actions/script" # script-by-digest endpoint
  c.timeout   = 20                                   # hard per-run timeout (seconds)
  c.logger    = Rails.logger
end
```

`configure` validates fail-closed at boot: a missing `secret` or `fetch_url` raises immediately.

Other tunables (with defaults): `clock_skew` (300s replay window half-width), `cache_dir`
(`tmp/rootcause/actions`, set `nil` for memory-only), `capture_stdout` (true), `max_stdout_bytes`
(64 KiB), `max_backtrace_lines` (50), `http_open_timeout` / `http_read_timeout`.

## Mount

Explicit mount — least magic, easiest to restrict at the edge:

```ruby
# config/routes.rb
mount RootCause::ActionRunner::RackApp.new => RootCause::ActionRunner.config.mount_at
```

**Recommended (documented, not enforced in v1):** restrict the route to rootcause's egress IP at the
edge, and run under a least-privileged DB role where feasible.

## What it does, in order (fail-closed at every step)

1. **Verify** `X-Webhook-Signature: sha256=<hex>` over the **raw** body (HMAC-SHA256, constant-time).
2. **Replay-guard** — reject if `issued_at` is outside ±`clock_skew`, or `nonce` was already seen.
3. **Validate params** against the `schema` carried in the invocation (defense in depth).
4. **Resolve the script by digest** — cache hit (`sha256 == digest`) or fetch + verify; mismatch is a
   hard refuse.
5. **Bind + execute** — params as a frozen, symbol-keyed hash, **as data, never interpolated into
   source**; last expression is the JSON-able return value.
6. **Hard timeout** + rescue everything → structured `error{class, message, backtrace}`.
7. **Return signed JSON** — `{ ok, return_value | error, stdout, duration_ms }`. Logs `action_id`,
   `digest`, param **keys**, `ok`, `duration_ms` — never the secret or param values.

## Security posture (honest caveats)

- **Not a sandbox.** Runs in-process as the app, full privileges. The boundary is: approved +
  digest-pinned scripts only, signature + replay on the channel, params bound as data, dual-sided
  audit. Real isolation is a later runtime swap.
- **`Timeout.timeout` is a backstop, not a transaction boundary** — it raises asynchronously and can
  fire mid-transaction. Actions must be written idempotent and safe to retry.
- **The digest is the authorization unit.** A body runs **iff** its `sha256` equals the
  `script_digest` in the signed invocation.

## Multi-worker deployments

The default nonce store is an in-process, TTL-pruned set — correct for a **single process**. Across
workers a replay could slip through on a second worker, so inject a shared store (anything responding
to `add?(nonce, ttl:)`, e.g. a `Rails.cache`-backed adapter using `write(unless_exist: true)`):

```ruby
runner = RootCause::ActionRunner::Runner.new(RootCause::ActionRunner.config, nonce_store: MyCacheStore.new)
mount RootCause::ActionRunner::RackApp.new(runner: runner) => "/rootcause/action"
```

Likewise, `capture_stdout` swaps the **process-global** `$stdout` for the duration of a run; under a
multi-threaded server that briefly intercepts other threads' output. Set `capture_stdout = false` if
that matters in your deployment.

## Development

```bash
bundle install
bundle exec rake        # standardrb (lint) + rspec
```
