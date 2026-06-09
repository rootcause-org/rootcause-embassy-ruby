# frozen_string_literal: true

RSpec.describe RootCause::ActionRunner::Result do
  it "maps CallbackPayload JSON to symbol-keyed, frozen accessors with markdown draft/note" do
    result = described_class.from_payload(
      "analysis_id" => "run-1",
      "metadata" => {"resource_type" => "SupportTicket", "resource_id" => 42},
      "draft" => {"body_markdown" => "**hi**", "body_html" => "<b>hi</b>"},
      "notes" => [
        {"kind" => "summary", "body_markdown" => "the summary [trace](https://x)", "body_html" => "<p>s</p>"},
        {"kind" => "widget", "body_markdown" => "a widget", "body_html" => "<p>w</p>"}
      ],
      "actions" => [{"id" => "a1", "label" => "Approve", "description" => "d", "url" => "https://x", "color" => "green"}],
      "reasoning_steps" => ["looked", "concluded"],
      "attachments" => [{"filename" => "f.txt", "mime_type" => "text/plain", "content_base64" => "eA=="}]
    )

    expect(result.analysis_id).to eq("run-1")
    expect(result.metadata).to eq({resource_type: "SupportTicket", resource_id: 42})
    expect(result.draft).to eq("**hi**")
    expect(result.note).to eq("the summary [trace](https://x)")
    expect(result.actions.first[:label]).to eq("Approve")
    expect(result.reasoning_steps).to eq(["looked", "concluded"])
    expect(result.attachments.first[:filename]).to eq("f.txt")
    expect(result).to be_frozen
    expect(result.metadata).to be_frozen
  end

  describe "draft (markdown)" do
    it "surfaces the draft's body_markdown as a string" do
      result = described_class.from_payload("draft" => {"body_markdown" => "# Draft", "body_html" => "<h1>Draft</h1>"})
      expect(result.draft).to eq("# Draft")
    end

    it "falls back to body_html only when markdown is absent" do
      result = described_class.from_payload("draft" => {"body_html" => "<p>only html</p>"})
      expect(result.draft).to eq("<p>only html</p>")
    end

    it "is nil when the draft node is absent or empty" do
      expect(described_class.from_payload({}).draft).to be_nil
      expect(described_class.from_payload("draft" => {"body_markdown" => ""}).draft).to be_nil
    end
  end

  describe "note (summary note, markdown)" do
    it "selects the summary note's body_markdown and ignores widget notes" do
      result = described_class.from_payload(
        "notes" => [
          {"kind" => "widget", "body_markdown" => "widget one"},
          {"kind" => "summary", "body_markdown" => "the summary"},
          {"kind" => "widget", "body_markdown" => "widget two"}
        ]
      )
      expect(result.note).to eq("the summary")
    end

    it "falls back to body_html for the summary note when markdown is absent" do
      result = described_class.from_payload(
        "notes" => [{"kind" => "summary", "body_html" => "<p>summary html</p>"}]
      )
      expect(result.note).to eq("<p>summary html</p>")
    end

    it "falls back to the first note when none is marked summary" do
      result = described_class.from_payload("notes" => [{"body_markdown" => "lone note"}])
      expect(result.note).to eq("lone note")
    end

    it "is nil when notes is absent or empty" do
      expect(described_class.from_payload({}).note).to be_nil
      expect(described_class.from_payload("notes" => []).note).to be_nil
    end
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
