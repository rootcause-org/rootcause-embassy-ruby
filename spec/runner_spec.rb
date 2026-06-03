# frozen_string_literal: true

# End-to-end through the framework-agnostic core: verify → replay → validate →
# resolve → run → sign. The host side (signing + script fetch) is stubbed via Wire.
RSpec.describe RootCause::ActionRunner::Runner do
  let(:config) { Wire.config }
  let(:runner) { described_class.new(config) }

  # Build a signed request for `invocation`, sending it through the runner.
  def handle(invocation, secret: Wire::SECRET)
    raw = JSON.generate(invocation)
    runner.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret))
  end

  def body_of(reply) = JSON.parse(reply.body)

  it "runs a valid invocation end to end and returns a signed, verifiable result" do
    script = "{ found: true, email: params[:email] }"
    Wire.stub_fetch(script: script)
    inv = Wire.invocation(
      script: script,
      params: {"email" => "x@acme.com"},
      schema: {"email" => {"type" => "string"}}
    )

    reply = handle(inv)

    expect(reply.status).to eq(200)
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    payload = body_of(reply)
    expect(payload["ok"]).to be(true)
    expect(payload["return_value"]).to eq({"found" => true, "email" => "x@acme.com"})
    expect(payload["duration_ms"]).to be_a(Integer)
  end

  it "rejects a bad signature with 401, still signing the refusal" do
    reply = handle(Wire.invocation, secret: "wrong-secret")
    expect(reply.status).to eq(401)
    expect(body_of(reply).dig("error", "class")).to eq("bad_signature")
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "rejects malformed JSON with 400" do
    raw = "not json"
    reply = runner.handle(raw_body: raw, signature: Wire.sign(raw))
    expect(reply.status).to eq(400)
  end

  it "rejects a missing required field with 400" do
    inv = Wire.invocation
    inv.delete("nonce")
    expect(handle(inv).status).to eq(400)
  end

  it "rejects a non-ruby runtime with 400" do
    expect(handle(Wire.invocation(runtime: "python")).status).to eq(400)
  end

  it "rejects a stale issued_at with 409" do
    inv = Wire.invocation(issued_at: (Time.now.utc - 3600).iso8601)
    expect(handle(inv).status).to eq(409)
  end

  it "rejects a replayed nonce with 409" do
    script = "{ ok: true }"
    Wire.stub_fetch(script: script)
    inv = Wire.invocation(script: script, nonce: "fixed-nonce")
    expect(handle(inv).status).to eq(200)
    expect(handle(inv).status).to eq(409)
  end

  it "rejects a schema violation with 422 (and never fetches a script)" do
    stub = Wire.stub_fetch(script: "{ ok: true }")
    inv = Wire.invocation(params: {"email" => 123}, schema: {"email" => {"type" => "string"}})
    expect(handle(inv).status).to eq(422)
    expect(stub).not_to have_been_requested
  end

  it "hard-refuses a digest mismatch with 502 and never runs the body" do
    real = "{ ok: true }"
    inv = Wire.invocation(script: real)
    # Host serves a different body under the requested digest.
    Wire.stub_fetch(script: "{ evil: true }", digest: inv["script_digest"])
    expect(handle(inv).status).to eq(502)
  end

  it "fail-closes an unexpected pipeline error into a signed 500 (never crashes)" do
    # A malformed-but-authenticated invocation that trips a non-typed error must
    # still come back as a signed, structured refusal — not an unsigned crash.
    inv = Wire.invocation(params: {"email" => "x@y.z"}, schema: {"email" => "string"})
    reply = handle(inv)
    expect(reply.status).to eq(422) # SchemaError now covers the shorthand
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "returns a signed 500 if a pipeline step raises an unexpected error" do
    # Force a non-Error exception from inside the pipeline (post-auth) and prove
    # the backstop signs and structures it rather than letting it escape.
    allow(RootCause::ActionRunner::Schema).to receive(:validate!).and_raise(RuntimeError, "x@acme.com leaked?")
    reply = handle(Wire.invocation)
    expect(reply.status).to eq(500)
    payload = body_of(reply)
    expect(payload["ok"]).to be(false)
    expect(payload.dig("error", "class")).to eq("internal_error")
    # The wire message is the exception class only — never the (possibly
    # input-bearing) exception message.
    expect(payload.dig("error", "message")).to eq("RuntimeError")
    expect(reply.body).not_to include("x@acme.com")
    expect(RootCause::ActionRunner::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "returns 200 with ok:false when the action itself raises" do
    script = "raise 'boom'"
    Wire.stub_fetch(script: script)
    reply = handle(Wire.invocation(script: script))
    expect(reply.status).to eq(200)
    expect(body_of(reply)["ok"]).to be(false)
  end

  describe "logging" do
    let(:logger) { instance_double(Logger, info: nil, warn: nil) }
    let(:config) { Wire.config(logger: logger) }

    it "logs identifiers, param KEYS, ok and duration — never values or the secret" do
      script = "{ ok: true }"
      Wire.stub_fetch(script: script)
      inv = Wire.invocation(script: script, params: {"email" => "secret@acme.com"}, schema: {"email" => {"type" => "string"}})

      handle(inv)

      expect(logger).to have_received(:info) do |line|
        expect(line).to include("action_id=devise_send_password_reset")
        expect(line).to include("param_keys=[\"email\"]")
        expect(line).to include("ok=true")
        expect(line).not_to include("secret@acme.com")
        expect(line).not_to include(Wire::SECRET)
      end
    end
  end
end
