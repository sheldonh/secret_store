require 'spec_helper'

describe SecretStore do
  it "is semantically versioned" do
    semver_regexp = /^((\d+)\.(\d+)\.(\d+))(?:-([\dA-Za-z\-]+(?:\.[\dA-Za-z\-]+)*))?(?:\+([\dA-Za-z\-]+(?:\.[\dA-Za-z\-]+)*))?$/
    expect( SecretStore::VERSION ).to match semver_regexp
  end
end
