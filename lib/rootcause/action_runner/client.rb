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
      # correlation), the host-managed conversation `session_id` (opaque — store and
      # forward on the next turn, never interpret), and the host's queue status.
      Analysis = Struct.new(:analysis_id, :session_id, :status, keyword_init: true)

      # What capture_sent_message returns: `ok` is always true on a 2xx; `id` is
      # the host's sent_messages row id when it echoes one (nil if it doesn't).
      SentMessage = Struct.new(:id, :ok, keyword_init: true)

      def initialize(config)
        @config = config
      end

      # @param session_id [String, nil] a prior turn's host-minted session id. When
      #   present, this turn continues that conversation — send ONLY the new
      #   subject/body, never prior history (the host keeps it). Opaque to the gem.
      # @return [Analysis]
      # @raise [TriggerError] non-2xx, malformed response, or transport failure
      # @raise [ArgumentError] missing trigger_url, or an over-cap/malformed attachment
      def start_analysis(subject:, body:, attachments: [], metadata: {}, session_id: nil)
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
        # Only carry session_id on a follow-up; the first turn omits it and the host
        # mints one, returned in the 202 below.
        payload["session_id"] = session_id unless blank?(session_id)
        raw = JSON.generate(payload)

        response = post(url, raw, transport_error: TriggerError, label: "analysis trigger")
        analysis = parse(response)
        log(analysis, metadata, payload["attachments"].size)
        analysis
      end

      # Fire-and-forget: hand rootcause the actual reply a human agent sent (after
      # editing the proposed draft), keyed to the same `session_id` as the analysis
      # so the host can learn the proposed-vs-sent delta. Pure outbound POST — no
      # analysis, no result handler. The host re-verifies on the RAW bytes, so the
      # payload key order here is irrelevant; only the signed bytes matter.
      #
      # @param sent_body [String] the reply that actually left the building (required)
      # @param session_id [String] the same handle passed to start_analysis (required)
      # @param proposed_body [String, nil] what rootcause proposed; omit if unknown
      # @param sender [String, nil] who sent it (agent label/name)
      # @param metadata [Hash] correlation (keys logged, values never)
      # @return [SentMessage] frozen, `ok: true` (with the host's id when echoed)
      # @raise [SentMessageError] non-2xx, malformed response, or transport failure
      # @raise [ArgumentError] missing sent_message_url, or blank sent_body/session_id
      def capture_sent_message(sent_body:, session_id:, proposed_body: nil, sender: nil, metadata: {})
        url = @config.sent_message_url
        raise ArgumentError, "RootCause::ActionRunner: sent_message_url is not configured" if blank?(url)
        raise ArgumentError, "RootCause::ActionRunner: sent_body is required" if blank?(sent_body)
        raise ArgumentError, "RootCause::ActionRunner: session_id is required" if blank?(session_id)

        metadata ||= {}
        sent = {"body" => sent_body}
        sent["sender"] = sender unless blank?(sender)
        payload = {
          "type" => "sent_message",
          "session_id" => session_id,
          "sent" => sent
        }
        # Absent `proposed` tells the host to treat the reply as pure signal.
        payload["proposed"] = {"body" => proposed_body} unless blank?(proposed_body)
        payload["metadata"] = metadata
        payload["nonce"] = SecureRandom.uuid
        payload["issued_at"] = Time.now.utc.iso8601
        raw = JSON.generate(payload)

        response = post(url, raw, transport_error: SentMessageError, label: "sent-message capture")
        result = parse_sent_message(response)
        log_sent_message(session_id, metadata, sent_body, proposed_body)
        result
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

      # Sign the RAW body and POST it. Transport-layer failures (Net::HTTP / SSL /
      # Timeout / URI) collapse to `transport_error` so each caller surfaces its own
      # exception type for the caller to rescue and decide to retry.
      def post(url, raw, transport_error:, label:)
        uri = URI(url)
        request = Net::HTTP::Post.new(uri)
        request["content-type"] = "application/json"
        request[Signature::HEADER] = Signature.sign(raw, secret: @config.secret)
        request.body = raw

        Http.perform(uri, request, open_timeout: @config.http_open_timeout, read_timeout: @config.http_read_timeout)
      rescue => e
        raise transport_error, "#{label} failed: #{e.class}: #{e.message}"
      end

      def parse(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise TriggerError, "analysis trigger returned #{response.code}"
        end

        data = JSON.parse(response.body.to_s)
        unless data.is_a?(Hash) && present?(data["analysis_id"])
          raise TriggerError, "analysis trigger response missing analysis_id"
        end

        Analysis.new(
          analysis_id: data["analysis_id"],
          session_id: data["session_id"],
          status: data["status"]
        ).freeze
      rescue JSON::ParserError
        raise TriggerError, "analysis trigger response was not valid JSON"
      end

      # A 2xx is success; the body is optional. When the host echoes a row id
      # (`sent_message_id` or `id`), carry it back for the caller's correlation.
      def parse_sent_message(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise SentMessageError, "sent-message capture returned #{response.code}"
        end

        body = response.body.to_s
        id = nil
        unless body.empty?
          data = JSON.parse(body)
          id = data["sent_message_id"] || data["id"] if data.is_a?(Hash)
        end
        SentMessage.new(id: id, ok: true).freeze
      rescue JSON::ParserError
        raise SentMessageError, "sent-message capture response was not valid JSON"
      end

      # Customer-side audit: session_id, metadata KEYS only (never values), and the
      # body BYTE sizes — never the bodies themselves or the secret.
      def log_sent_message(session_id, metadata, sent_body, proposed_body)
        return unless @config.logger

        @config.logger.info(
          "[rootcause-sent-message] session_id=#{session_id} " \
          "metadata_keys=#{metadata_keys(metadata)} " \
          "sent_bytes=#{sent_body.to_s.bytesize} proposed_bytes=#{proposed_body.to_s.bytesize}"
        )
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
