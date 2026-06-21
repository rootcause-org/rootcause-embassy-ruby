# frozen_string_literal: true

require "net/http"
require "uri"
require "json"
require "digest"
require "fileutils"

module RootCause
  module Embassy
    # Resolve an action's script body by digest. The digest is the authorization
    # unit: a body runs IFF sha256(body) equals the digest in the signed
    # invocation, so every body — cache hit or freshly fetched — is re-hashed and
    # verified here before it leaves this class. The cache is therefore immutable
    # and self-verifying: a tampered or stale cache entry simply fails the hash
    # check and is re-fetched.
    #
    # Lookup order: process memory → disk (tmp/rootcause/actions/<hex>.rb) → fetch
    # from the rootcause host. Misses fall through; a digest mismatch anywhere is
    # a hard refuse (ResolveError), never a run.
    class Resolver
      def initialize(config)
        @config = config
        @memory = {} # hex digest => verified script body
        @mutex = Mutex.new
      end

      # @return [String] the digest-verified script body
      # @raise [ResolveError] on any failure to produce a verified body
      def resolve(action_id:, digest:, project_id:)
        hex = self.class.hex(digest)

        cached = read_cache(hex)
        return cached if cached

        body = fetch(action_id: action_id, digest: digest, project_id: project_id)
        verify_digest!(body, hex)
        write_cache(hex, body)
        body
      end

      # Strip the "sha256:" label and return the bare lowercased hex, validating
      # shape so a malformed digest can't become a path-traversal filename.
      def self.hex(digest)
        raw = digest.to_s.sub(/\Asha256:/, "").downcase
        unless /\A[0-9a-f]{64}\z/.match?(raw)
          raise ResolveError, "malformed script_digest"
        end
        raw
      end

      private

      def read_cache(hex)
        if (body = @mutex.synchronize { @memory[hex] })
          return body
        end

        body = read_disk(hex)
        return nil unless body
        # Disk is shared, mutable state — re-verify before trusting or promoting.
        return nil unless Digest::SHA256.hexdigest(body) == hex

        @mutex.synchronize { @memory[hex] = body }
        body
      end

      def read_disk(hex)
        path = disk_path(hex)
        return nil unless path && File.file?(path)

        File.binread(path)
      rescue SystemCallError
        nil
      end

      def write_cache(hex, body)
        @mutex.synchronize { @memory[hex] = body }

        path = disk_path(hex)
        return unless path

        FileUtils.mkdir_p(File.dirname(path))
        # Write-then-rename so a reader never sees a half-written body.
        tmp = "#{path}.#{Process.pid}.tmp"
        File.binwrite(tmp, body)
        File.rename(tmp, path)
      rescue SystemCallError
        # Disk caching is best-effort; memory cache already holds the body.
        nil
      end

      def disk_path(hex)
        dir = @config.cache_dir
        return nil if dir.nil? || dir.to_s.empty?

        File.join(dir, "#{hex}.rb")
      end

      def verify_digest!(body, hex)
        actual = Digest::SHA256.hexdigest(body)
        return if actual == hex

        raise ResolveError, "digest mismatch: fetched body hashes to #{actual}, expected #{hex}"
      end

      def fetch(action_id:, digest:, project_id:)
        # The host's script-fetch keys the project off `project_id` (to pick the registry + the secret
        # it verifies this request's signature with) and verifies over the WHOLE query string — so it
        # must ride the query AND the signed bytes, not just be known to us. Order matches the host's
        # raw-query verification: action_id, digest, project_id.
        query = URI.encode_www_form([["action_id", action_id], ["digest", digest], ["project_id", project_id]])
        uri = URI(@config.fetch_url)
        uri.query = query

        response = http_get(uri, signature: Signature.sign(query, secret: @config.secret))

        unless response.is_a?(Net::HTTPSuccess)
          raise ResolveError, "script fetch returned #{response.code}"
        end

        body = response.body.to_s
        verify_response_signature!(response, body)
        extract_script(body, action_id: action_id, digest: digest)
      rescue ResolveError
        raise
      rescue => e
        # Net::HTTP / SSL / Timeout / URI failures all collapse to a fail-closed
        # resolve error — the run never proceeds without a verified body.
        raise ResolveError, "script fetch failed: #{e.class}: #{e.message}"
      end

      def http_get(uri, signature:)
        request = Net::HTTP::Get.new(uri)
        request[Signature::HEADER] = signature

        Http.perform(uri, request, open_timeout: @config.http_open_timeout, read_timeout: @config.http_read_timeout)
      end

      # The script's integrity rests on the digest check, but the channel is also
      # signed both ways: a present-but-invalid response signature is a hard
      # refuse. We require the header so a misconfigured host fails closed.
      def verify_response_signature!(response, raw_body)
        header = response[Signature::HEADER]
        return if Signature.valid?(header, raw_body, secret: @config.secret)

        raise ResolveError, "script fetch response signature invalid"
      end

      def extract_script(raw_body, action_id:, digest:)
        payload = JSON.parse(raw_body)
        unless payload.is_a?(Hash) && payload["script"].is_a?(String)
          raise ResolveError, "script fetch response missing script"
        end
        if payload["digest"] && payload["digest"].to_s != digest.to_s
          raise ResolveError, "script fetch returned a different digest"
        end
        payload["script"]
      rescue JSON::ParserError
        raise ResolveError, "script fetch response was not valid JSON"
      end
    end
  end
end
