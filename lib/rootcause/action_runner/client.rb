# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "time"
require "securerandom"

module RootCause
  module ActionRunner
    # The outbound trigger — the opposite direction of the invocation flow, on the
    # SAME reverse-channel secret (no new crypto, no new secret). `start_analysis`
    # builds the documented body, signs the RAW JSON, POSTs it to the rootcause
    # host, and returns the run's `analysis_id` for the caller to persist alongside
    # its own resource (correlation is by that id + the echoed `metadata`).
    #
    # Failures are the caller's to handle, never swallowed: a non-2xx / malformed
    # response / transport failure raises TriggerError; an over-cap or malformed
    # attachment raises ArgumentError before anything is sent.
    class Client
      # What start_analysis returns: the rootcause run id (for audit / idempotency /
      # correlation) and the host's queue status.
      Analysis = Struct.new(:analysis_id, :status, keyword_init: true)

      def initialize(config)
        @config = config
      end

      # @return [Analysis]
      # @raise [TriggerError] non-2xx, malformed response, or transport failure
      # @raise [ArgumentError] missing trigger_url, or an over-cap/malformed attachment
      def start_analysis(subject:, body:, attachments: [], metadata: {})
        url = @config.trigger_url
        raise ArgumentError, "RootCause::ActionRunner: trigger_url is not configured" if blank?(url)

        metadata ||= {}
        payload = {
          "subject" => subject,
          "body" => body,
          "attachments" => normalize_attachments(attachments),
          "metadata" => metadata,
          "nonce" => SecureRandom.uuid,
          "issued_at" => Time.now.utc.iso8601
        }
        raw = JSON.generate(payload)

        analysis = parse(post(url, raw))
        log(analysis, metadata, payload["attachments"].size)
        analysis
      end

      private

      # Validate + canonicalize attachments. Decode each (strict base64) to measure
      # the cap and prove it is well-formed; fail loud BEFORE sending so the caller
      # learns of a bad payload without a round-trip. `content_base64` rides on the
      # wire verbatim (the customer already encoded it).
      def normalize_attachments(attachments)
        Array(attachments).each_with_index.map do |att, i|
          att = stringify(att, i)
          b64 = att["content_base64"].to_s
          decoded_bytes = decode!(b64, i)

          if decoded_bytes > @config.max_attachment_bytes
            raise ArgumentError,
              "attachment #{i}: #{decoded_bytes} decoded bytes exceeds max_attachment_bytes (#{@config.max_attachment_bytes})"
          end

          {
            "filename" => att["filename"],
            "mime_type" => att["mime_type"],
            "content_base64" => b64
          }
        end
      end

      def stringify(att, i)
        raise ArgumentError, "attachment #{i}: must be an object" unless att.is_a?(Hash)

        att.each_with_object({}) { |(k, v), h| h[k.to_s] = v }
      end

      # Strict RFC 4648 decode via String#unpack (stdlib, no `base64` require) —
      # returns the decoded byte length. Raises on malformed/whitespaced input.
      def decode!(b64, i)
        b64.unpack1("m0").bytesize
      rescue ArgumentError
        raise ArgumentError, "attachment #{i}: content_base64 is not valid (strict) base64"
      end

      def post(url, raw)
        uri = URI(url)
        request = Net::HTTP::Post.new(uri)
        request["content-type"] = "application/json"
        request[Signature::HEADER] = Signature.sign(raw, secret: @config.secret)
        request.body = raw

        Http.perform(uri, request, open_timeout: @config.http_open_timeout, read_timeout: @config.http_read_timeout)
      rescue => e
        # Net::HTTP / SSL / Timeout / URI failures collapse to a TriggerError the
        # caller can rescue and decide to retry.
        raise TriggerError, "analysis trigger failed: #{e.class}: #{e.message}"
      end

      def parse(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise TriggerError, "analysis trigger returned #{response.code}"
        end

        data = JSON.parse(response.body.to_s)
        unless data.is_a?(Hash) && present?(data["analysis_id"])
          raise TriggerError, "analysis trigger response missing analysis_id"
        end

        Analysis.new(analysis_id: data["analysis_id"], status: data["status"]).freeze
      rescue JSON::ParserError
        raise TriggerError, "analysis trigger response was not valid JSON"
      end

      # Customer-side audit: the run id, metadata KEYS only (never values — they
      # transit rootcause), and the attachment count. Never the secret.
      def log(analysis, metadata, attachment_count)
        return unless @config.logger

        @config.logger.info(
          "[rootcause-trigger] analysis_id=#{analysis.analysis_id} " \
          "metadata_keys=#{metadata_keys(metadata)} attachments=#{attachment_count}"
        )
      end

      def metadata_keys(metadata) = metadata.is_a?(Hash) ? metadata.keys.map(&:to_s).sort : []
      def blank?(value) = value.nil? || value.to_s.empty?
      def present?(value) = !value.nil? && value.to_s != ""
    end
  end
end
