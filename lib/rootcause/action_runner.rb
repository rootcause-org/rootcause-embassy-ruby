# frozen_string_literal: true

require_relative "action_runner/version"
require_relative "action_runner/errors"
require_relative "action_runner/config"
require_relative "action_runner/signature"
require_relative "action_runner/schema"
require_relative "action_runner/replay"
require_relative "action_runner/resolver"
require_relative "action_runner/executor"
require_relative "action_runner/runner"
require_relative "action_runner/rack"

module RootCause
  # The customer-side action runner. Configure once at boot; the mounted RackApp
  # then turns each signed, digest-pinned invocation into a signed result.
  module ActionRunner
    class << self
      # Configure once in an initializer; validates fail-closed at boot and builds
      # the singleton Runner (with its nonce store and script/compile caches).
      #
      #   RootCause::ActionRunner.configure do |c|
      #     c.secret    = ENV.fetch("ROOTCAUSE_ACTION_SECRET")
      #     c.fetch_url = "https://<rootcause>/actions/script"
      #     c.timeout   = 20
      #     c.logger    = Rails.logger
      #   end
      def configure
        config = Config.new
        yield config if block_given?
        config.validate!
        @config = config
        @runner = Runner.new(config)
        config
      end

      def config
        @config || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      def runner
        @runner || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      # Test/boot-order seam: drop the configured singletons.
      def reset!
        @config = nil
        @runner = nil
      end
    end
  end
end
