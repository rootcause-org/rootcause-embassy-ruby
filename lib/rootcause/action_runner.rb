# frozen_string_literal: true

require_relative "action_runner/version"
require_relative "action_runner/errors"
require_relative "action_runner/config"
require_relative "action_runner/signature"
require_relative "action_runner/http"
require_relative "action_runner/schema"
require_relative "action_runner/replay"
require_relative "action_runner/resolver"
require_relative "action_runner/executor"
require_relative "action_runner/runner"
require_relative "action_runner/rack"
require_relative "action_runner/result"
require_relative "action_runner/result_handler"
require_relative "action_runner/client"
require_relative "action_runner/result_rack"

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
        @client = Client.new(config)
        @result_receiver = ResultReceiver.new(config)
        config
      end

      def config
        @config || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      def runner
        @runner || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      def client
        @client || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      def result_receiver
        @result_receiver || raise("RootCause::ActionRunner is not configured — call .configure first")
      end

      # Outbound trigger: ask rootcause to analyze something and get an analysis_id
      # back to persist alongside your resource. See Client#start_analysis.
      def start_analysis(...)
        client.start_analysis(...)
      end

      # Fire-and-forget: hand rootcause the reply a human agent actually sent (after
      # editing the proposed draft), keyed to the analysis `session_id`. See
      # Client#capture_sent_message.
      def capture_sent_message(...)
        client.capture_sent_message(...)
      end

      # Test/boot-order seam: drop the configured singletons.
      def reset!
        @config = nil
        @runner = nil
        @client = nil
        @result_receiver = nil
      end
    end
  end
end
