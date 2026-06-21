# frozen_string_literal: true

require "net/http"

module RootCause
  module Embassy
    # Single Net::HTTP entry point shared by both directions that dial the
    # rootcause origin: the inbound script-fetch (Resolver, GET) and the outbound
    # analysis trigger (Client, POST). It centralizes the SSL + timeout wiring so
    # the two stay identical; callers build the Request (verb, headers, body) and
    # hand it here to run. Stdlib only, no new dep.
    module Http
      module_function

      def perform(uri, request, open_timeout:, read_timeout:)
        Net::HTTP.start(
          uri.host, uri.port,
          use_ssl: uri.scheme == "https",
          open_timeout: open_timeout,
          read_timeout: read_timeout
        ) { |http| http.request(request) }
      end
    end
  end
end
