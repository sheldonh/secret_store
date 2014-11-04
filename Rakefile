require 'bundler/gem_tasks'

begin
  require 'rubygems'
  require 'cucumber'
  require 'cucumber/rake/task'
  require 'rspec/core/rake_task'

  Cucumber::Rake::Task.new(:features) do |t|
    t.cucumber_opts = 'features --format pretty'
  end

  RSpec::Core::RakeTask.new(:spec)

  task :test => [:spec, :features]
  task :default => [:test]
rescue LoadError
  # Development dependencies not loaded
end
