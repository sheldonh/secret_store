require 'spec_helper'

require 'secret_store/store_api'
require 'secret_store/store_provider/memory'

describe SecretStore::StoreAPI do

  let(:namespace) { 'starjuice:secret_store:test:v1' }
  let(:provider) { SecretStore::StoreProvider::Memory.new }
  let(:subject) { described_class.new(provider, namespace) }

  describe '.new(provider, namespace)' do

    it 'validates the namespace'

  end

  describe '#set(property, value)' do

    it 'sets the value of the property in the correct namespace' do
      subject.set('deep-dark-secret', 'unbreakable ciphertext')
      expect( provider.get(namespace, 'deep-dark-secret') ).to eq 'unbreakable ciphertext'
    end

  end

end
