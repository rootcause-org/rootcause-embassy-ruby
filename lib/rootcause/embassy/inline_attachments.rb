# frozen_string_literal: true

require "base64"
require "digest"
require "tempfile"

module RootCause
  module Embassy
    # Signed bytes stay separate from business params. Shape/cap failures refuse;
    # corrupt authorized bytes remain a per-file outcome so primary work can finish.
    module InlineAttachments
      MAX_FILES = 5
      MAX_FILE_BYTES = 8 * 1024 * 1024
      MAX_TOTAL_BYTES = 20 * 1024 * 1024
      MAX_BODY_BYTES = 32 * 1024 * 1024
      MAX_ENCODED_FILE_BYTES = ((MAX_FILE_BYTES + 2) / 3) * 4
      MAX_ENCODED_TOTAL_BYTES = ((MAX_TOTAL_BYTES + 2) / 3) * 4 + MAX_FILES * 4
      UUID_PATTERN = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
      BASE64_PATTERN = /\A[A-Za-z0-9+\/]*={0,2}\z/
      METADATA_KEYS = %w[attachment_id filename mime_type size_bytes].freeze
      CHUNK_BYTES = 64 * 1024

      module_function

      def validate!(invocation)
        return {} unless invocation.key?("attachments")

        map = invocation["attachments"]
        invalid! unless map.is_a?(Hash)
        ids = []
        total = encoded_total = 0
        map.each do |name, descriptors|
          schema = invocation["schema"]
          params = invocation["params"]
          invalid! unless schema.is_a?(Hash) && schema[name].is_a?(Hash) && schema[name]["type"] == "string[]" &&
            params.is_a?(Hash) && params[name].is_a?(Array) && descriptors.is_a?(Array)
          descriptors.each do |descriptor|
            validate_descriptor!(descriptor)
            ids << descriptor["attachment_id"]
            # Byte caps bind delivered bytes; an over-cap file arrives as `unavailable` with its real size.
            total += descriptor["size_bytes"] unless descriptor.key?("error")
            encoded_total += descriptor.fetch("content_base64", "").bytesize
            invalid! if ids.length > MAX_FILES || total > MAX_TOTAL_BYTES || encoded_total > MAX_ENCODED_TOTAL_BYTES
          end
          invalid! unless descriptors.map { |descriptor| descriptor["attachment_id"] } == params[name]
        end
        invalid! unless ids.uniq.length == ids.length
        map
      end

      def validate_descriptor!(descriptor)
        invalid! unless descriptor.is_a?(Hash)
        id = descriptor["attachment_id"]
        invalid! unless id.is_a?(String) && UUID_PATTERN.match?(id)
        %w[filename mime_type].each do |name|
          value = descriptor[name]
          invalid! unless value.is_a?(String) && !value.empty? && !value.include?("\0")
        end
        size = descriptor["size_bytes"]
        invalid! unless size.is_a?(Integer) && size >= 0
        if descriptor.key?("error")
          invalid! unless descriptor.keys.sort == (METADATA_KEYS + ["error"]).sort && descriptor["error"] == "unavailable"
        else
          invalid! unless descriptor.keys.sort == (METADATA_KEYS + %w[sha256 content_base64]).sort && size <= MAX_FILE_BYTES
          invalid! unless descriptor["sha256"].is_a?(String) && /\A[0-9a-f]{64}\z/.match?(descriptor["sha256"])
          encoded = descriptor["content_base64"]
          invalid! unless encoded.is_a?(String) && encoded.bytesize <= MAX_ENCODED_FILE_BYTES
        end
      end

      def with_materialized(map)
        files = []
        materialized = map.transform_values do |descriptors|
          descriptors.map do |descriptor|
            metadata = descriptor.slice(*METADATA_KEYS)
            if descriptor.key?("error")
              metadata.merge("error" => "unavailable")
            else
              file = Tempfile.new("rootcause-action-attachment")
              files << file
              file.binmode
              decode!(descriptor, file) ? metadata.merge("path" => file.path) : metadata.merge("error" => "corrupt")
            end
          end
        end
        yield materialized
      ensure
        files&.each(&:close!)
      end

      def decode!(descriptor, file)
        encoded = descriptor.fetch("content_base64")
        return false unless encoded.bytesize % 4 == 0 && BASE64_PATTERN.match?(encoded)

        size = 0
        digest = Digest::SHA256.new
        offset = 0
        while offset < encoded.bytesize
          bytes = Base64.strict_decode64(encoded.byteslice(offset, CHUNK_BYTES))
          size += bytes.bytesize
          return false if size > descriptor["size_bytes"]

          file.write(bytes)
          digest.update(bytes)
          offset += CHUNK_BYTES
        end
        file.flush
        file.rewind
        size == descriptor["size_bytes"] && digest.hexdigest == descriptor["sha256"]
      rescue ArgumentError
        false
      end

      def invalid! = raise(InvalidRequest, "invalid inline attachment metadata, selection, or limits")
    end
  end
end
