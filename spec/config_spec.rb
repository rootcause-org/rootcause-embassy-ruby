# frozen_string_literal: true

RSpec.describe RootCause::ActionRunner::Config do
  it "validates fail-closed when the secret is missing" do
    cfg = described_class.new
    cfg.fetch_url = "https://x"
    expect { cfg.validate! }.to raise_error(ArgumentError, /secret/)
  end

  it "validates fail-closed when fetch_url is missing" do
    cfg = described_class.new
    cfg.secret = "s"
    expect { cfg.validate! }.to raise_error(ArgumentError, /fetch_url/)
  end

  it "rejects a non-positive timeout" do
    cfg = described_class.new
    cfg.secret = "s"
    cfg.fetch_url = "https://x"
    cfg.timeout = 0
    expect { cfg.validate! }.to raise_error(ArgumentError, /timeout/)
  end

  it "carries sensible defaults" do
    cfg = described_class.new
    expect(cfg.mount_at).to eq("/rootcause/action")
    expect(cfg.clock_skew).to eq(300)
    expect(cfg.timeout).to eq(20)
  end
end

RSpec.describe RootCause::ActionRunner do
  it "raises a clear error if used before configuration" do
    described_class.reset!
    expect { described_class.runner }.to raise_error(/not configured/)
  end

  it "builds a runner once configured" do
    described_class.configure { |c|
      c.secret = "s"
      c.fetch_url = "https://x"
    }
    expect(described_class.runner).to be_a(RootCause::ActionRunner::Runner)
    expect(described_class.config.secret).to eq("s")
  end
end
