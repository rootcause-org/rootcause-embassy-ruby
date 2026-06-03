# frozen_string_literal: true

require "rspec/core/rake_task"
require "standard/rake"

RSpec::Core::RakeTask.new(:spec)

# `bundle exec rake` → lint then test (see .claude/CLAUDE.md "Before reporting done").
task default: %i[standard spec]
