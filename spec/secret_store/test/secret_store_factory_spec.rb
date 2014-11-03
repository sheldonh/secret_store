require 'spec_helper'

require 'secret_store/test'

describe SecretStore::Test::SecretStoreFactory do

  describe '.fabricate(namespace: string, key: string)' do

    it 'creates a secret store' do
      secret_store = SecretStore::Test::SecretStoreFactory.fabricate(namespace: 'starjuice:secret_store:test:v1', key: 'password')
      expect( secret_store ).to be_a SecretStore::Base
    end

  end

end
