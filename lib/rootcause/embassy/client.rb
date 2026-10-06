# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "time"
require "securerandom"

module RootCause
  module Embassy
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

      # What capture_sent_message returns. Answers may spawn a child analysis,
      # whose id and accepted status are returned alongside any sent-message id.
      SentMessage = Struct.new(:id, :ok, :status, :analysis_id, keyword_init: true)

      def initialize(config)
        @config = config
      end

      # @param session_id [String, nil] a prior turn's host-minted session id. When
      #   present, this turn continues that conversation — send ONLY the new
      #   subject/body, never prior history (the host keeps it). Opaque to the gem.
      # @param tenant [String, nil] optional rootcause tenant slug for tenant-enabled projects.
      # @param principal [Hash, nil] optional identity assertion about WHO this
      #   trigger is on behalf of — `{kind:, external_id:, asserted_by: nil,
      #   assurance: nil, tenant_hint: nil, source_metadata: nil}`. The customer app
      #   asserts it from its OWN authenticated session; it must never be derived from
      #   model output or from anything the end user can set. Dormant unless the
      #   project declares `scope_claims`, in which case the host resolves it into
      #   typed data-plane claims. Omit entirely when there is no authenticated user.
      # @param context_refs [Array<Hash>, nil] at most one `{kind: "action_run", id:}`
      #   whose id is the `RC_ACTION_RUN_ID` an action stored with the record it
      #   created — never a param or user text. Lets the analysis read the chat that
      #   led to that action, when its approved manifest delegates it.
      # @return [Analysis]
      # @raise [TriggerError] non-2xx, malformed response, or transport failure
      # @raise [Error] chat-only/half-wired setup: ANALYSIS_TRIGGER_URL_REQUIRED or
      #   ACTION_PLANE_DISABLED; malformed context_refs: ANALYSIS_REQUEST_INVALID
      #   (all carry code/hint/docs; Error < ArgumentError)
      # @raise [ArgumentError] an over-cap (single or aggregate)/malformed attachment, or a principal
      #   without both kind and external_id
      def start_analysis(subject:, body:, attachments: [], metadata: {}, session_id: nil, tenant: nil, principal: nil, project_id: nil, context_refs: nil)
        url = @config.trigger_url
        if Util.blank?(url)
          raise Error.public("ANALYSIS_TRIGGER_URL_REQUIRED", "Set ROOTCAUSE_TRIGGER_URL before starting an analysis.")
        end

        metadata ||= {}
        context_refs = normalize_context_refs(context_refs)
        # Key order is not contract, but this one reproduces every trigger golden
        # byte-for-byte. Only carry session_id on a follow-up; the first turn omits
        # it and the host mints one, returned in the 202 below.
        payload = {
          "subject" => subject,
          "body" => body,
          "attachments" => normalize_attachments(attachments),
          "metadata" => metadata
        }
        payload["session_id"] = session_id unless Util.blank?(session_id)
        payload["context_refs"] = context_refs unless context_refs.empty?
        payload["principal"] = normalize_principal(principal) unless principal.nil?
        payload["nonce"] = SecureRandom.uuid
        payload["issued_at"] = Time.now.utc.iso8601
        payload["tenant"] = tenant unless Util.blank?(tenant)
        raw = JSON.generate(payload)

        response = post(url, raw, project_id: project_id, transport_error: TriggerError, label: "analysis trigger")
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
      # @param sent_body [String, nil] the reply that actually left the building;
      #   required unless answers are present
      # @param answers [Array<Hash>] answers to a prior result's questions; valid
      #   alone or alongside sent_body
      # @param session_id [String] the same handle passed to start_analysis (required)
      # @param proposed_body [String, nil] what rootcause proposed; omit if unknown
      # @param sender [String, nil] who sent it (agent label/name)
      # @param metadata [Hash] correlation — NOT free-form here (unlike the trigger's
      #   metadata): the host strict-decodes exactly `{resource_type, resource_id}`,
      #   both STRINGS, and any other key is a 400. `resource_id` becomes the host's
      #   thread id. Keys are logged, values never.
      # @return [SentMessage] frozen, `ok: true` (with the host's id when echoed)
      # @raise [SentMessageError] non-2xx, malformed response, or transport failure
      # @raise [Error] SENT_MESSAGE_URL_REQUIRED, SESSION_ID_REQUIRED,
      #   SENT_MESSAGE_CONTENT_REQUIRED, SENT_MESSAGE_INVALID, or ACTION_PLANE_DISABLED
      def capture_sent_message(session_id:, sent_body: nil, proposed_body: nil, sender: nil, metadata: {}, answers: [], project_id: nil)
        url = @config.sent_message_url
        if Util.blank?(url)
          raise Error.public("SENT_MESSAGE_URL_REQUIRED", "Set ROOTCAUSE_SENT_MESSAGE_URL before capturing a sent message.")
        end
        if Util.blank?(session_id)
          raise Error.public("SESSION_ID_REQUIRED", "Set session_id to the ReplyPen session being continued.")
        end

        metadata ||= {}
        answers = normalize_answers(answers)
        if Util.blank?(sent_body) && answers.empty?
          raise Error.public(
            "SENT_MESSAGE_CONTENT_REQUIRED",
            "Set sent_body, answers, or both before capturing a sent message."
          )
        end

        payload = {
          "type" => "sent_message",
          "session_id" => session_id
        }
        unless Util.blank?(sent_body)
          sent = {"body" => sent_body}
          sent["sender"] = sender unless Util.blank?(sender)
          payload["sent"] = sent
        end
        # Absent `proposed` tells the host to treat the reply as pure signal.
        payload["proposed"] = {"body" => proposed_body} unless Util.blank?(proposed_body)
        payload["metadata"] = metadata
        payload["answers"] = answers unless answers.empty?
        payload["nonce"] = SecureRandom.uuid
        payload["issued_at"] = Time.now.utc.iso8601
        raw = JSON.generate(payload)

        response = post(url, raw, project_id: project_id, transport_error: SentMessageError, label: "sent-message capture")
        result = parse_sent_message(response)
        log_sent_message(session_id, metadata, sent_body, proposed_body, answers.length)
        result
      end

      private

      # Fields the host's ProjectPrincipal accepts, in wire spelling. The trigger
      # route strict-decodes (unknown field → 400), so anything else is dropped here
      # rather than turned into a 400 the caller can't read, and a nil is OMITTED
      # rather than sent as null.
      PRINCIPAL_FIELDS = %w[kind external_id asserted_by assurance tenant_hint source_metadata].freeze

      # The host rejects a partial assertion (kind without external_id or vice-versa)
      # because it would silently resolve to zero claims and degrade to tenant-only
      # scope. Fail here instead, before the round-trip.
      def normalize_principal(principal)
        raise ArgumentError, "principal must be an object" unless principal.is_a?(Hash)

        fields = stringify_keys(principal)
        missing = %w[kind external_id].reject { |f| Util.present?(fields[f]) }
        raise ArgumentError, "principal requires #{missing.join(" and ")}" unless missing.empty?

        PRINCIPAL_FIELDS.each_with_object({}) do |field, out|
          value = fields[field]
          out[field] = value unless value.nil?
        end
      end

      CONTEXT_REF_ID_PATTERN = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
      CONTEXT_REFS_HINT = 'Pass at most one context_ref, exactly {kind: "action_run", id: <stored RC_ACTION_RUN_ID>}.'

      # The host strict-decodes this (any deviation is a 400 the caller can't
      # read), so mirror its shape rules here and fail before the round-trip.
      def normalize_context_refs(refs)
        return [] if refs.nil?
        unless refs.is_a?(Array) && refs.length <= 1
          raise Error.public("ANALYSIS_REQUEST_INVALID", CONTEXT_REFS_HINT, "context_refs must be an array of at most one entry")
        end

        refs.map do |ref|
          fields = ref.is_a?(Hash) ? stringify_keys(ref) : {}
          valid = fields.keys.sort == %w[id kind] &&
            ["action_run", :action_run].include?(fields["kind"]) &&
            fields["id"].is_a?(String) && CONTEXT_REF_ID_PATTERN.match?(fields["id"])
          raise Error.public("ANALYSIS_REQUEST_INVALID", CONTEXT_REFS_HINT, "context_refs entry is invalid") unless valid

          {"kind" => "action_run", "id" => fields["id"]}
        end
      end

      # Validate + canonicalize attachments. Decode each (strict base64) to measure
      # it against the per-attachment and aggregate caps and to prove it is
      # well-formed; fail loud BEFORE sending so the caller learns of a bad payload
      # without a round-trip. `content_base64` rides on the wire verbatim (the
      # customer already encoded it).
      def normalize_attachments(attachments)
        total_bytes = 0

        Array(attachments).each_with_index.map do |att, i|
          raise ArgumentError, "attachment #{i}: must be an object" unless att.is_a?(Hash)

          att = stringify_keys(att)
          b64 = att["content_base64"].to_s
          decoded_bytes = decode!(b64, i)

          if decoded_bytes > @config.max_attachment_bytes
            raise ArgumentError,
              "attachment #{i}: #{decoded_bytes} decoded bytes exceeds max_attachment_bytes (#{@config.max_attachment_bytes})"
          end

          # The host caps the AGGREGATE too, so a set of individually-legal files can
          # still be refused. Fail here, before the round-trip.
          total_bytes += decoded_bytes
          if total_bytes > @config.max_total_attachment_bytes
            raise ArgumentError,
              "attachments: #{total_bytes} decoded bytes exceeds max_total_attachment_bytes (#{@config.max_total_attachment_bytes})"
          end

          {
            "filename" => att["filename"],
            "mime_type" => att["mime_type"],
            "content_base64" => b64
          }
        end
      end

      def normalize_answers(answers)
        Array(answers).each_with_index.map do |answer, index|
          unless answer.is_a?(Hash)
            raise Error.public("SENT_MESSAGE_INVALID", "Set each answer to an id and a non-empty string values list.")
          end

          fields = stringify_keys(answer)
          id = fields["id"]
          values = fields["values"]
          unless Util.present?(id) && values.is_a?(Array) && !values.empty? && values.all? { |value| value.is_a?(String) }
            raise Error.public(
              "SENT_MESSAGE_INVALID",
              "Set each answer to an id and a non-empty string values list.",
              "answer #{index} is invalid"
            )
          end

          {"id" => id.to_s, "values" => values}
        end
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
      def post(url, raw, project_id:, transport_error:, label:)
        secret = @config.outbound_secret_for(project_id)
        begin
          uri = URI(url)
          request = Net::HTTP::Post.new(uri)
          request["content-type"] = "application/json"
          request[Signature::HEADER] = Signature.sign(raw, secret: secret)
          request.body = raw

          Http.perform(uri, request, open_timeout: @config.http_open_timeout, read_timeout: @config.http_read_timeout)
        rescue => e
          raise transport_error, "#{label} failed: #{e.class}: #{e.message}"
        end
      end

      def parse(response)
        unless response.is_a?(Net::HTTPSuccess)
          code = host_error_code(response.body)
          message = "analysis trigger returned #{response.code}"
          message += " (#{code})" if code
          raise TriggerError.new(message, status: response.code.to_i, code: code)
        end

        data = JSON.parse(response.body.to_s)
        unless data.is_a?(Hash) && Util.present?(data["analysis_id"])
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

      HOST_ERROR_CODE_PATTERN = /\A[A-Z][A-Z0-9_]{0,63}\z/

      # Only a well-formed code leaves the body: it reaches the error message,
      # and arbitrary host text must not.
      def host_error_code(body)
        data = JSON.parse(body.to_s)
        code = data["error"]["code"] if data.is_a?(Hash) && data["error"].is_a?(Hash)
        (code.is_a?(String) && HOST_ERROR_CODE_PATTERN.match?(code)) ? code : nil
      rescue JSON::ParserError
        nil
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
        SentMessage.new(
          id: id,
          ok: true,
          status: data.is_a?(Hash) ? data["status"] : nil,
          analysis_id: data.is_a?(Hash) ? data["analysis_id"] : nil
        ).freeze
      rescue JSON::ParserError
        raise SentMessageError, "sent-message capture response was not valid JSON"
      end

      # Customer-side audit: session_id, metadata KEYS only (never values), and the
      # body BYTE sizes — never the bodies themselves or the secret.
      def log_sent_message(session_id, metadata, sent_body, proposed_body, answers_count)
        return unless @config.logger

        @config.logger.info(
          "[rootcause-sent-message] session_id=#{session_id} " \
          "metadata_keys=#{metadata_keys(metadata)} " \
          "sent_bytes=#{sent_body.to_s.bytesize} proposed_bytes=#{proposed_body.to_s.bytesize} " \
          "answers=#{answers_count}"
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
      def stringify_keys(hash) = hash.each_with_object({}) { |(key, value), out| out[key.to_s] = value }
    end
  end
end
