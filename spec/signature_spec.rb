# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Signature do
  let(:secret) { "s3cr3t" }
  let(:body) { %({"a":1}) }

  it "round-trips: a freshly signed payload verifies" do
    sig = described_class.sign(body, secret: secret)
    expect(sig).to start_with("sha256=")
    expect(described_class.valid?(sig, body, secret: secret)).to be(true)
  end

  it "rejects a forged signature" do
    expect(described_class.valid?("sha256=deadbeef", body, secret: secret)).to be(false)
  end

  it "rejects a signature made with the wrong secret" do
    sig = described_class.sign(body, secret: "other")
    expect(described_class.valid?(sig, body, secret: secret)).to be(false)
  end

  it "rejects a tampered body" do
    sig = described_class.sign(body, secret: secret)
    expect(described_class.valid?(sig, %({"a":2}), secret: secret)).to be(false)
  end

  it "treats a missing/nil signature as invalid (never raises)" do
    expect(described_class.valid?(nil, body, secret: secret)).to be(false)
    expect(described_class.valid?("", body, secret: secret)).to be(false)
  end

  describe ".secure_compare" do
    it "is false when lengths differ" do
      expect(described_class.secure_compare("a", "aa")).to be(false)
    end

    it "is true for equal strings" do
      expect(described_class.secure_compare("abc", "abc")).to be(true)
    end
  end
end
