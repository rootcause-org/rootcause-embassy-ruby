# frozen_string_literal: true

RSpec.describe RootCause::ActionRunner::Result do
  it "maps CallbackPayload JSON to symbol-keyed, frozen accessors" do
    result = described_class.from_payload(
      "analysis_id" => "run-1",
      "metadata" => {"resource_type" => "SupportTicket", "resource_id" => 42},
      "draft" => {"body_markdown" => "**hi**", "body_html" => "<b>hi</b>"},
      "note" => {"body_markdown" => "n", "body_html" => "<p>n</p>", "body_text" => "n"},
      "actions" => [{"id" => "a1", "label" => "Approve", "description" => "d", "url" => "https://x", "color" => "green"}],
      "reasoning_steps" => ["looked", "concluded"],
      "attachments" => [{"filename" => "f.txt", "mime_type" => "text/plain", "content_base64" => "eA=="}]
    )

    expect(result.analysis_id).to eq("run-1")
    expect(result.metadata).to eq({resource_type: "SupportTicket", resource_id: 42})
    expect(result.draft).to eq({body_markdown: "**hi**", body_html: "<b>hi</b>"})
    expect(result.note[:body_text]).to eq("n")
    expect(result.actions.first[:label]).to eq("Approve")
    expect(result.reasoning_steps).to eq(["looked", "concluded"])
    expect(result.attachments.first[:filename]).to eq("f.txt")
    expect(result).to be_frozen
    expect(result.metadata).to be_frozen
  end

  it "exposes the session_id from the result envelope" do
    result = described_class.from_payload("analysis_id" => "r", "session_id" => "sess-1")
    expect(result.session_id).to eq("sess-1")
  end

  it "leaves session_id nil when the envelope omits it" do
    expect(described_class.from_payload("analysis_id" => "r").session_id).to be_nil
  end

  it "is ok? when there is no decline" do
    expect(described_class.from_payload("analysis_id" => "r").ok?).to be(true)
  end

  it "is not ok? when declined, exposing the reason" do
    result = described_class.from_payload(
      "analysis_id" => "r", "decline" => {"reason" => "out of scope"}
    )
    expect(result.ok?).to be(false)
    expect(result.decline).to eq({reason: "out of scope"})
  end

  it "defaults absent optional fields to nil and absent collections to empty" do
    result = described_class.from_payload("analysis_id" => "r")
    expect(result.draft).to be_nil
    expect(result.note).to be_nil
    expect(result.decline).to be_nil
    expect(result.metadata).to eq({})
    expect(result.actions).to eq([])
    expect(result.reasoning_steps).to eq([])
    expect(result.attachments).to eq([])
  end

  it "accepts already-symbol-keyed input too" do
    result = described_class.from_payload(analysis_id: "r", metadata: {resource_id: 7})
    expect(result.metadata).to eq({resource_id: 7})
  end
end
