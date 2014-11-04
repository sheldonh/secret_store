require 'spec_helper'

require 'secret_store/store_provider/memory'

describe SecretStore::StoreProvider::Memory do

  describe '.new(initial = {})' do

    it 'can be initialized empty' do
      expect { described_class.new }.to_not raise_error
    end

  end

  describe '.set(namespace, property, value)' do

    it 'sets the value of a property in a namespace' do
      subject.set('starjuice:secret_store:test:v1', 'deep-dark-secret', 'unbreakable ciphertext')
      expect( subject.get('starjuice:secret_store:test:v1', 'deep-dark-secret') ).to eq 'unbreakable ciphertext'
    end
  end

  describe '.get(namespace, property)' do

    it 'returns nil for an unknown namespace' do
      expect( subject.get('starjuice:secret_store:test:v1', 'deep-dark-secret') ).to be_nil
    end

    it 'returns nil for an unknown property' do
      subject.set('starjuice:secret_store:test:v1', 'not-what-you-are-looking-for', 'unbreakable ciphertext')
      expect( subject.get('starjuice:secret_store:test:v1', 'deep-dark-secret') ).to be_nil
    end

  end

end
