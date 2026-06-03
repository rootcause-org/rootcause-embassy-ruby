# frozen_string_literal: true

require "logger"

module RootCause
  module ActionRunner
    # Customer-supplied configuration, set once in an initializer. Values are read
    # on every request, so the same Config instance is shared and treated as
    # effectively immutable after boot.
    class Config
      # Reverse-channel HMAC secret (per project). Distinct from the email
      # `webhook_secret`. Held via ENV customer-side. Never logged.
      attr_accessor :secret

      # The single mounted route, e.g. "/rootcause/action".
      attr_accessor :mount_at

      # Script-by-digest endpoint on the rootcause host, hit on a cache miss.
      attr_accessor :fetch_url

      # Hard per-run wall-clock timeout in seconds (Timeout backstop).
      attr_accessor :timeout

      # Replay window half-width in seconds: an invocation is fresh iff
      # |now - issued_at| <= clock_skew. ±5 min per the spec.
      attr_accessor :clock_skew

      # Where digest-keyed script bodies are cached on disk. Immutable + self-
      # verifying (re-hashed on read); nil disables disk caching (memory only).
      attr_accessor :cache_dir

      # Capture the action's $stdout into the result. See Executor for the
      # documented multi-threaded caveat (global $stdout swap).
      attr_accessor :capture_stdout

      # Truncate captured stdout to this many bytes (inline JSON only, no files).
      attr_accessor :max_stdout_bytes

      # Truncate the rescued backtrace to this many frames.
      attr_accessor :max_backtrace_lines

      # Customer-side logger. Logs action_id/digest/param KEYS/ok/duration_ms only.
      attr_accessor :logger

      # HTTP open/read timeouts for the script fetch (seconds).
      attr_accessor :http_open_timeout, :http_read_timeout

      def initialize
        @mount_at = "/rootcause/action"
        @timeout = 20
        @clock_skew = 300
        @cache_dir = "tmp/rootcause/actions"
        @capture_stdout = true
        @max_stdout_bytes = 64 * 1024
        @max_backtrace_lines = 50
        @logger = Logger.new($stdout)
        @http_open_timeout = 5
        @http_read_timeout = 15
      end

      # Fail closed at boot rather than on the first invocation: a missing secret
      # or fetch_url is a deployment mistake, not a runtime condition.
      def validate!
        raise ArgumentError, "RootCause::ActionRunner: secret is required" if blank?(secret)
        raise ArgumentError, "RootCause::ActionRunner: fetch_url is required" if blank?(fetch_url)
        raise ArgumentError, "RootCause::ActionRunner: timeout must be positive" unless timeout.to_f > 0
        self
      end

      private

      def blank?(value) = value.nil? || value.to_s.empty?
    end
  end
end
