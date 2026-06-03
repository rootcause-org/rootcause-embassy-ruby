# frozen_string_literal: true

require_relative "lib/rootcause/action_runner/version"

Gem::Specification.new do |spec|
  spec.name = "rootcause-action-runner"
  spec.version = RootCause::ActionRunner::VERSION
  spec.authors = ["PJ Muller"]
  spec.email = ["info@probackup.io"]

  spec.summary = "Customer-side action runner for rootcause's action plane."
  spec.description = <<~DESC
    A thin Ruby gem the customer mounts once in their Rails app. It receives a
    signed, digest-pinned invocation from the rootcause host, resolves the
    action's script by digest, runs it inline with a hard timeout, and returns a
    signed structured result. No executable code ever travels on the wire.
  DESC
  spec.homepage = "https://github.com/rootcause-org/rootcause-action-gem"
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb", "SPEC.md", "README.md"]
  spec.require_paths = ["lib"]

  # Runtime: stdlib only (Net::HTTP, OpenSSL, Digest, Timeout, JSON). No new deps
  # without a recorded reason — see .claude/CLAUDE.md.

  spec.add_development_dependency "rack", "~> 3.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "standard", "~> 1.40"
  # Dev only: stub the rootcause origin (script fetch) so the suite needs no live
  # host. Not a runtime dependency — the gem fetches with stdlib Net::HTTP.
  spec.add_development_dependency "webmock", "~> 3.23"
end
