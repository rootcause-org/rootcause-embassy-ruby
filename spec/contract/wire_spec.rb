# frozen_string_literal: true

require "digest"

# WIRE CONTRACT v1 — see WIRE-CONTRACT.md in rootcause-light.
#
# Pins the gem's conformance to the host↔gem wire contract so it can't silently
# regress. The fixtures under spec/fixtures/contract/ are CANONICAL golden bytes
# representing exactly what the Go host emits (no trailing newline). We sign and
# verify over those EXACT bytes — never a re-serialization — mirroring the host.
#
# Covered:
#   - the gem parses + handles a host-shaped Invocation (schema as an OBJECT keyed
#     by name with type+required, project_id present), and its dry_run variant;
#   - the gem verifies + extracts a signed FetchResponse;
#   - the gem PRODUCES a Result in the contract shape; and
#   - a refusal (schema violation) comes back as a SIGNED non-2xx body
#     {ok:false, error:{class,message}}.
RSpec.describe "WIRE CONTRACT v1" do
  fixture_dir = File.expand_path("../fixtures/contract", __dir__)

  # A real reverse-channel secret; the host signs the same canonical bytes with it.
  secret = "wire-contract-secret"

  define_method(:fixture_dir) { fixture_dir }
  define_method(:secret) { secret }

  # Raw fixture bytes, verbatim — asserting no trailing newline so the golden
  # bytes are what we sign/verify over (a stray newline would change the HMAC).
  def fixture(name)
    bytes = File.binread(File.join(fixture_dir, name))
    expect(bytes).not_to end_with("\n")
    bytes
  end

  def sign(bytes) = RootCause::ActionRunner::Signature.sign(bytes, secret: secret)

  # A wide clock_skew so the static fixture issued_at never trips the freshness
  # window — the fixtures pin SHAPE, not freshness (freshness is covered elsewhere).
  let(:config) do
    cfg = RootCause::ActionRunner::Config.new
    cfg.secret = secret
    cfg.fetch_url = "https://rootcause.example.com/actions/script"
    cfg.logger = nil
    cfg.cache_dir = nil
    cfg.clock_skew = 100 * 365 * 24 * 3600 # a century — fixtures are static
    cfg
  end
  let(:runner) { RootCause::ActionRunner::Runner.new(config) }

  def body_of(reply) = JSON.parse(reply.body)

  # Stub the host's script-fetch with the canonical signed FetchResponse bytes.
  def stub_canonical_fetch
    body = fixture("fetch_response.json")
    WebMock.stub_request(:get, /rootcause\.example\.com/).to_return(
      status: 200,
      body: body,
      headers: {RootCause::ActionRunner::Signature::HEADER => sign(body)}
    )
  end

  it "parses + handles a canonical host Invocation (object-keyed schema, project_id) and produces a Result in contract shape" do
    stub_canonical_fetch
    raw = fixture("invocation.json")

    reply = runner.handle(raw_body: raw, signature: sign(raw))

    expect(reply.status).to eq(200)
    payload = body_of(reply)
    # Result contract shape: ok, return_value, stdout, error, duration_ms.
    expect(payload.keys).to contain_exactly("ok", "return_value", "error", "stdout", "duration_ms")
    expect(payload["ok"]).to be(true)
    expect(payload["return_value"]).to eq({"found" => true, "email" => "x@acme.com"})
    expect(payload["error"]).to be_nil
    expect(payload["stdout"]).to be_a(String)
    expect(payload["duration_ms"]).to be_a(Integer)
    # Signed over the EXACT reply bytes.
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: secret)).to be(true)
  end

  it "handles the dry_run Invocation variant: validate-only, would_execute, signed" do
    stub_canonical_fetch
    raw = fixture("invocation_dry_run.json")

    reply = runner.handle(raw_body: raw, signature: sign(raw))

    expect(reply.status).to eq(200)
    payload = body_of(reply)
    expect(payload["ok"]).to be(true)
    expect(payload["return_value"]).to eq({"dry_run" => true, "would_execute" => true})
    expect(payload["stdout"]).to eq("")
    expect(payload["error"]).to be_nil
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: secret)).to be(true)
  end

  it "verifies + extracts a canonical signed FetchResponse (digest-verified)" do
    body = fixture("fetch_response.json")
    WebMock.stub_request(:get, /rootcause\.example\.com/).to_return(
      status: 200,
      body: body,
      headers: {RootCause::ActionRunner::Signature::HEADER => sign(body)}
    )
    parsed = JSON.parse(body)

    script = RootCause::ActionRunner::Resolver.new(config).resolve(
      action_id: parsed["action_id"],
      digest: parsed["digest"],
      project_id: "00000000-0000-0000-0000-000000000000"
    )

    expect(script).to eq(parsed["script"])
  end

  it "refuses a schema violation as a SIGNED non-2xx {ok:false, error:{class,message}}" do
    # No fetch should ever happen — schema runs before resolve.
    stub = WebMock.stub_request(:get, /rootcause\.example\.com/)
    raw = fixture("invocation_schema_violation.json")

    reply = runner.handle(raw_body: raw, signature: sign(raw))

    expect(reply.status).to eq(422)
    expect(reply.status).not_to be_between(200, 299)
    payload = body_of(reply)
    expect(payload["ok"]).to be(false)
    expect(payload.dig("error", "class")).to eq("schema_violation")
    expect(payload.dig("error", "message")).to be_a(String)
    expect(stub).not_to have_been_requested
    # The refusal is signed so the host can trust it.
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: secret)).to be(true)
  end

  it "ties the invocation and fetch fixtures together by digest (the authorization unit)" do
    inv = JSON.parse(fixture("invocation.json"))
    fetch = JSON.parse(fixture("fetch_response.json"))
    expect(inv["script_digest"]).to eq(fetch["digest"])
    expect("sha256:#{Digest::SHA256.hexdigest(fetch["script"])}").to eq(fetch["digest"])
  end
end
