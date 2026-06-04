# frozen_string_literal: true

module RootCause
  module ActionRunner
    # Base class for the customer's async-result handler. Subclass it in app/ and
    # implement #process(result); the result route lazy-loads it by name on every
    # dispatch (reload-safe) and calls #process inline, under the configured
    # timeout. Keep it a quick, idempotent write — offloading to a job reintroduces
    # the infra this feature exists to avoid.
    #
    # MUST be idempotent: rootcause redelivers on a lost ack, and a retry outside
    # the replay window carries a fresh nonce and WILL dispatch again. Upsert by
    # `metadata` (or `analysis_id`) — never blind-insert.
    class ResultHandler
      def process(result)
        raise NotImplementedError, "#{self.class}#process must be implemented"
      end
    end
  end
end
