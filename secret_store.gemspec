# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'secret_store/version'

Gem::Specification.new do |spec|
  spec.name          = "secret_store"
  spec.version       = SecretStore::VERSION
  spec.authors       = ["Sheldon Hearn"]
  spec.email         = ["sheldonh@starjuice.net"]
  spec.summary       = %q{Toolkit for storing secrets securely}
  spec.description   = %q{An experimental Ruby toolkit for storing secrets securely.}
  spec.homepage      = "https://github.com/sheldonh/secret_store"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.1"
  spec.add_development_dependency "cucumber", "~> 1.3"
  spec.add_development_dependency "redis", "~> 3.1"
  spec.add_development_dependency "byebug", "~> 3.5"
end
