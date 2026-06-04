# frozen_string_literal: true

module RootCause
  module ActionRunner
    # The async analysis result handed to the customer's ResultHandler. Field names
    # are taken VERBATIM from rootcause's webhook.CallbackPayload and ReplyPen's
    # contract so all three products serialize identically. A frozen, symbol-keyed
    # value object — the handler reads a stable, immutable bag.
    #
    # The SPEC §1 human-in-the-loop invariant is preserved by the field split:
    # draft / note / reasoning_steps / attachments are informational (safe to
    # auto-burn into the customer's records); `actions[]` are vetted side-effects
    # rootcause PROPOSES — the customer renders them for a human to click, and they
    # ride back through the gem's existing invocation route. The gem never auto-runs
    # them, so no "autonomous action" feature is needed.
    class Result
      attr_reader :analysis_id, :metadata, :draft, :note, :actions,
        :reasoning_steps, :attachments, :decline

      def initialize(analysis_id:, metadata:, draft:, note:, actions:, reasoning_steps:, attachments:, decline:)
        @analysis_id = analysis_id
        @metadata = metadata
        @draft = draft
        @note = note
        @actions = actions
        @reasoning_steps = reasoning_steps
        @attachments = attachments
        @decline = decline
        freeze
      end

      # An analysis that produced output, not a decline.
      def ok? = decline.nil?

      # Build from parsed result JSON (string- or symbol-keyed). Optional scalar
      # fields absent → nil; collection fields absent → empty. Everything is
      # deep-symbolized and frozen.
      def self.from_payload(payload)
        data = deep(payload)
        data = {} unless data.is_a?(Hash)

        new(
          analysis_id: data[:analysis_id],
          metadata: data[:metadata] || EMPTY_HASH,
          draft: data[:draft],
          note: data[:note],
          actions: data[:actions] || EMPTY_ARRAY,
          reasoning_steps: data[:reasoning_steps] || EMPTY_ARRAY,
          attachments: data[:attachments] || EMPTY_ARRAY,
          decline: data[:decline]
        )
      end

      EMPTY_HASH = {}.freeze
      EMPTY_ARRAY = [].freeze

      # Deep symbol-keying + freeze. Symbol keys match the documented accessors
      # (e.g. result.metadata[:resource_id]); freezing keeps the bag immutable so a
      # handler can't mutate state that another (redelivered) dispatch would read.
      def self.deep(value)
        case value
        when Hash
          value.each_with_object({}) { |(k, v), h| h[k.to_sym] = deep(v) }.freeze
        when Array
          value.map { |e| deep(e) }.freeze
        when String
          value.frozen? ? value : value.dup.freeze
        else
          value
        end
      end
    end
  end
end
