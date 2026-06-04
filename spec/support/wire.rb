# frozen_string_literal: true

require "digest"

# Test helpers that play the rootcause host: build/sign invocations and stub the
# script-by-digest endpoint exactly as the gem expects to verify it.
module Wire
  SECRET = "test-reverse-channel-secret"
  FETCH_URL = "https://rootcause.test/actions/script"
  TRIGGER_URL = "https://rootcause.test/analyses/test-project"

  module_function

  def sign(payload, secret: SECRET)
    RootCause::ActionRunner::Signature.sign(payload, secret: secret)
  end

  def digest_of(script)
    "sha256:#{Digest::SHA256.hexdigest(script)}"
  end

  # A valid invocation body (Ruby hash). Override any field via kwargs.
  def invocation(script: "{ ok: true }", **overrides)
    {
      "action_id" => "devise_send_password_reset",
      "script_digest" => digest_of(script),
      "params" => {},
      "schema" => {},
      "runtime" => "ruby",
      "project_id" => "00000000-0000-0000-0000-000000000000",
      "nonce" => "nonce-#{rand(1_000_000)}",
      "issued_at" => Time.now.utc.iso8601
    }.merge(overrides)
  end

  # Stub the host's script-fetch endpoint to return a signed body for `script`.
  # By default the returned digest is the true sha256 — pass `digest:` to forge.
  def stub_fetch(script:, digest: nil, action_id: "devise_send_password_reset", status: 200)
    digest ||= digest_of(script)
    body = JSON.generate(
      "action_id" => action_id,
      "digest" => digest,
      "script" => script,
      "runtime" => "ruby"
    )
    WebMock.stub_request(:get, /rootcause\.test/).to_return(
      status: status,
      body: body,
      headers: {RootCause::ActionRunner::Signature::HEADER => sign(body)}
    )
  end

  def config(**overrides)
    cfg = RootCause::ActionRunner::Config.new
    cfg.secret = SECRET
    cfg.fetch_url = FETCH_URL
    cfg.trigger_url = TRIGGER_URL
    cfg.logger = nil
    cfg.cache_dir = nil # memory-only in tests; no tmp pollution
    overrides.each { |k, v| cfg.public_send("#{k}=", v) }
    cfg
  end

  # --- async analysis ---

  # Stub the host's trigger endpoint, returning the documented 202 + analysis_id.
  def stub_trigger(analysis_id: "analysis-uuid-1", status: 202)
    WebMock.stub_request(:post, TRIGGER_URL).to_return(
      status: status,
      body: JSON.generate("analysis_id" => analysis_id, "status" => "queued"),
      headers: {"content-type" => "application/json"}
    )
  end

  # A valid result body (Ruby hash) as rootcause POSTs to the result route.
  # Override or add CallbackPayload fields via kwargs.
  def result(**overrides)
    {
      "analysis_id" => "analysis-uuid-1",
      "metadata" => {"resource_type" => "SupportTicket", "resource_id" => 42},
      "draft" => {"body_markdown" => "Hi there", "body_html" => "<p>Hi there</p>"},
      "note" => nil,
      "actions" => [],
      "reasoning_steps" => [],
      "attachments" => [],
      "decline" => nil,
      "nonce" => "result-nonce-#{rand(1_000_000)}",
      "issued_at" => Time.now.utc.iso8601
    }.merge(overrides)
  end
end
