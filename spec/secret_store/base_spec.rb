require 'spec_helper'

require 'secret_store/base'
require 'secret_store/store_provider/memory'
require 'secret_store/test'

describe SecretStore::Base do

  let(:store) { SecretStore::StoreAPI.new(SecretStore::StoreProvider::Memory.new, 'starjuice:secret_store:test:v1') }
  let(:cipher) { SecretStore::CipherAPI.new(SecretStore::Test::SnakeOilCipherProvider, 'password') }
  let(:marshal) { SecretStore::MarshalAPI.new(SecretStore::Test::RogueMarshalProvider) }
  subject { SecretStore::Base.new(store, cipher, marshal) }

  describe '#set_secret(secret_name, secret_value)' do

    it 'always returns nil' do
      expect( subject.set_secret('deep-dark-secret', 'The cake is a lie!') ).to be_nil
    end

    it 'sets the secret ciphertext in the store provider' do
      subject.set_secret('deep-dark-secret', 'The cake is a lie!')
      expect( store.get('deep-dark-secret') ).to match /snake oil/
    end

  end

  describe '#get_secret(secret_name)' do

    it 'returns nil for an unknown secret' do
      expect( subject.get_secret('deep-dark-secret') ).to be_nil
    end

    it 'returns the secret cleartext for a known secret' do
      subject.set_secret('deep-dark-secret', 'The cake is a lie!')
      expect( subject.get_secret('deep-dark-secret') ).to eq 'The cake is a lie!'
    end

  end

end
