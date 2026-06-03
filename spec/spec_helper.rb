# frozen_string_literal: true

require "rootcause-action-runner"
require "webmock/rspec"
require "json"
require "time"
require "cgi"
require "tmpdir"

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed

  config.after { RootCause::ActionRunner.reset! }
end

require_relative "support/wire"
