# frozen_string_literal: true

module RootCause
  module ActionRunner
    # Base for every refusal the runner raises before/around executing an action.
    #
    # Each carries an HTTP `status` and a stable `code` so the Rack shell can turn
    # it into a signed `{ ok: false, error: { class, message } }` body without a
    # giant case statement. Fail closed: every refusal is one of these.
    class Error < StandardError
      # HTTP status the Rack shell returns for this refusal.
      def status = 500

      # Stable machine code (snake_case) surfaced as the error `class` on the wire.
      def code = "error"
    end

    # Malformed request: unparseable JSON or missing required invocation fields.
    class InvalidRequest < Error
      def status = 400
      def code = "invalid_request"
    end

    # Signature missing or did not verify (constant-time) against the raw body.
    class SignatureError < Error
      def status = 401
      def code = "bad_signature"
    end

    # Replay guard tripped: `issued_at` outside the window or `nonce` already seen.
    class ReplayError < Error
      def status = 409
      def code = "replay"
    end

    # Params failed re-validation against the schema carried in the invocation.
    class SchemaError < Error
      def status = 422
      def code = "schema_violation"
    end

    # Could not produce a digest-verified script body: fetch non-2xx, transport
    # failure, or — the load-bearing one — sha256(body) != script_digest.
    class ResolveError < Error
      def status = 502
      def code = "resolve_failed"
    end
  end
end
