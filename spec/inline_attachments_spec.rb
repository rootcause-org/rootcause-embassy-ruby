# frozen_string_literal: true

RSpec.describe "signed inline action attachments" do
  let(:config) { Wire.config }
  let(:runner) { RootCause::Embassy::Runner.new(config) }
  let(:id) { "55555555-5555-5555-5555-555555555555" }
  let(:second_id) { "66666666-6666-6666-6666-666666666666" }
  let(:bytes) { "hello\x00".b * 12_000 }
  let(:descriptor) do
    {"attachment_id" => id, "filename" => "screen.png", "mime_type" => "image/png",
     "size_bytes" => bytes.bytesize, "sha256" => Digest::SHA256.hexdigest(bytes),
     "content_base64" => Base64.strict_encode64(bytes)}
  end
  let(:script) do
    <<~RUBY_SCRIPT
      map = JSON.parse(ENV.fetch("RC_ACTION_ATTACHMENTS"))
      file = map.fetch("files").first
      { "params" => params, "metadata" => map, "digest" => file["path"] && Digest::SHA256.file(file["path"]).hexdigest,
        "deadline" => ENV.fetch("RC_ACTION_DEADLINE_AT").to_f }
    RUBY_SCRIPT
  end

  def invocation(script: self.script, descriptors: [descriptor], **overrides)
    Wire.invocation(:script => script, "params" => {"files" => descriptors.map { |file| file["attachment_id"] }},
      "schema" => {"files" => {"type" => "string[]", "required" => false}},
      "attachments" => {"files" => descriptors}, **overrides)
  end

  def invoke(payload)
    raw = JSON.generate(payload)
    runner.handle(raw_body: raw, signature: Wire.sign(raw))
  end

  def result(payload = invocation)
    Wire.stub_fetch(script: script)
    reply = invoke(payload)
    expect(reply.status).to eq(200)
    JSON.parse(reply.body).fetch("return_value")
  end

  it "materializes binary chunks, preserves keyed metadata and params, and unlinks after success" do
    now = Time.now.to_f
    value = result
    file = value.fetch("metadata").fetch("files").first
    expect(value.fetch("params")).to eq("files" => [id])
    expect(value.fetch("digest")).to eq(Digest::SHA256.hexdigest(bytes))
    expect(file).to include(descriptor.slice("attachment_id", "filename", "mime_type", "size_bytes"))
    expect(file.keys).not_to include("content_base64", "sha256")
    expect(File).not_to exist(file.fetch("path"))
    expect(value.fetch("deadline")).to be_between(now + 17.8, now + 18.2)
  end

  it "uses the earlier total deadline after resolution consumes invocation budget" do
    config.timeout = 3
    config.total_deadline = 3.1
    resolver = instance_double(RootCause::Embassy::Resolver)
    allow(resolver).to receive(:resolve) {
      sleep 0.15
      script
    }
    local = RootCause::Embassy::Runner.new(config, resolver: resolver)
    raw = JSON.generate(invocation)
    started = Time.now.to_f
    reply = local.handle(raw_body: raw, signature: Wire.sign(raw))
    expect(JSON.parse(reply.body).dig("return_value", "deadline")).to be_between(started + 1.08, started + 1.12)
  end

  it "passes missing authorized bytes through as unavailable" do
    missing = descriptor.slice("attachment_id", "filename", "mime_type", "size_bytes").merge("error" => "unavailable")
    expect(result(invocation(descriptors: [missing])).dig("metadata", "files", 0)).to eq(missing)
  end

  it "keeps other authorized files when base64, size, or digest verification fails" do
    valid = descriptor.merge("attachment_id" => second_id)
    [descriptor.merge("content_base64" => "bad!"), descriptor.merge("size_bytes" => 0),
      descriptor.merge("sha256" => "0" * 64), descriptor.merge("content_base64" => "aGVs\nbG8="),
      descriptor.merge("content_base64" => "aGVsbG8=AAAA")].each do |bad|
      value = result(invocation(descriptors: [bad, valid]))
      files = value.fetch("metadata").fetch("files")
      expect(files.first).to include("error" => "corrupt")
      expect(files.first).not_to have_key("path")
      expect(files.last).to have_key("path")
      expect(File).not_to exist(files.last.fetch("path"))
    end
  end

  it "refuses malformed metadata, selection and schema before any resolve" do
    fetch = Wire.stub_fetch(script: script)
    bad_descriptors = [descriptor.merge("attachment_id" => "not-a-uuid"), descriptor.merge("filename" => ""),
      descriptor.merge("mime_type" => "x\0y"), descriptor.merge("size_bytes" => -1),
      descriptor.merge("size_bytes" => 1.5), descriptor.merge("sha256" => "A" * 64),
      descriptor.merge("error" => "unavailable"), descriptor.merge("surprise" => "value")]
    payloads = bad_descriptors.map { |bad| invocation(descriptors: [bad]) }
    payloads += [invocation("attachments" => nil), invocation("attachments" => []),
      invocation("params" => {"files" => [second_id]}), invocation("schema" => {"files" => {"type" => "string"}}),
      invocation(descriptors: [descriptor, descriptor]), invocation("attachments" => {"files" => "bad"})]
    payloads.each do |payload|
      reply = invoke(payload)
      expect(reply.status).to eq(400)
      expect(JSON.parse(reply.body).dig("error", "class")).to eq("invalid_request")
      expect(reply.signature).to eq(Wire.sign(reply.body))
    end
    expect(fetch).not_to have_been_requested
  end

  it "refuses declared and encoded caps before allocating decoded files" do
    max = RootCause::Embassy::InlineAttachments::MAX_FILE_BYTES
    unavailable = descriptor.slice("attachment_id", "filename", "mime_type", "size_bytes").merge("error" => "unavailable")
    oversized = descriptor.merge("content_base64" => "a" * (RootCause::Embassy::InlineAttachments::MAX_ENCODED_FILE_BYTES + 1))
    payloads = [invocation(descriptors: [descriptor.merge("size_bytes" => max + 1)]), invocation(descriptors: [oversized]),
      invocation(descriptors: 3.times.map { |n| unavailable.merge("attachment_id" => format("%08d-5555-5555-5555-555555555555", n), "size_bytes" => max) }),
      invocation(descriptors: 6.times.map { |n| unavailable.merge("attachment_id" => format("%08d-5555-5555-5555-555555555555", n)) })]
    expect(Base64).not_to receive(:strict_decode64)
    expect(Tempfile).not_to receive(:new)
    payloads.each { |payload| expect(invoke(payload).status).to eq(400) }
  end

  it "validates dry-run payloads without decoding, materializing, or executing" do
    Wire.stub_fetch(script: script)
    expect(Base64).not_to receive(:strict_decode64)
    expect(Tempfile).not_to receive(:new)
    reply = invoke(invocation("dry_run" => true))
    expect(JSON.parse(reply.body).fetch("return_value")).to eq("dry_run" => true, "would_execute" => true)
    expect(invoke(invocation(:descriptors => [descriptor.merge("filename" => "")], "dry_run" => true)).status).to eq(400)
  end

  it "restores stale variables and removes files after action error, execution timeout, and total timeout" do
    keys = RootCause::Embassy::Executor::ACTION_ENV_KEYS
    previous = keys.to_h { |key| [key, ENV[key]] }
    keys.each { |key| ENV[key] = "stale" }
    paths = []
    allow(Tempfile).to receive(:new).and_wrap_original { |original, *args| original.call(*args).tap { |file| paths << file.path } }
    ["raise 'boom'", "sleep 0.1"].each do |body|
      timeout_config = Wire.config(timeout: 0.02, total_deadline: 0.03)
      Wire.stub_fetch(script: body)
      raw = JSON.generate(invocation(script: body))
      reply = RootCause::Embassy::Runner.new(timeout_config).handle(raw_body: raw, signature: Wire.sign(raw))
      expect(JSON.parse(reply.body)["ok"]).to be(false)
      expect(keys.map { |key| ENV[key] }).to all(eq("stale"))
    end
    timeout_config = Wire.config(timeout: 0.1, total_deadline: 0.02)
    Wire.stub_fetch(script: "sleep 0.1")
    raw = JSON.generate(invocation(script: "sleep 0.1"))
    reply = RootCause::Embassy::Runner.new(timeout_config).handle(raw_body: raw, signature: Wire.sign(raw))
    expect(JSON.parse(reply.body)["ok"]).to be(false)
    expect(keys.map { |key| ENV[key] }).to all(eq("stale"))
    paths.each { |path| expect(File).not_to exist(path) }
  ensure
    previous&.each { |key, value| value ? ENV[key] = value : ENV.delete(key) }
  end

  it "clears stale file context on an invocation without attachments and restores absent env" do
    previous = ENV["RC_ACTION_ATTACHMENTS"]
    previous_deadline = ENV["RC_ACTION_DEADLINE_AT"]
    ENV["RC_ACTION_ATTACHMENTS"] = "stale"
    ENV.delete("RC_ACTION_DEADLINE_AT")
    body = "{ files: ENV['RC_ACTION_ATTACHMENTS'], deadline: ENV['RC_ACTION_DEADLINE_AT'] }"
    Wire.stub_fetch(script: body)
    value = JSON.parse(invoke(Wire.invocation(script: body)).body).fetch("return_value")
    expect(value["files"]).to be_nil
    expect(value["deadline"].to_f).to be > Time.now.to_f
    expect(ENV["RC_ACTION_ATTACHMENTS"]).to eq("stale")
    expect(ENV).not_to have_key("RC_ACTION_DEADLINE_AT")
  ensure
    previous ? ENV["RC_ACTION_ATTACHMENTS"] = previous : ENV.delete("RC_ACTION_ATTACHMENTS")
    previous_deadline ? ENV["RC_ACTION_DEADLINE_AT"] = previous_deadline : ENV.delete("RC_ACTION_DEADLINE_AT")
  end
end
