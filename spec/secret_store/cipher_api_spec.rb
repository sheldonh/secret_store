require 'spec_helper'

require 'secret_store/cipher_api'
require 'secret_store/test'

describe SecretStore::CipherAPI do

  let(:provider) { SecretStore::Test::SnakeOilCipherProvider }
  subject { described_class.new(provider, 'password') }

  describe '#.encrypt(cleartext)' do

    it 'returns the ciphertext of the cleartext, encrypted with the instance cipher and key' do
      expect( subject.encrypt('My little pony') ).to eq 'My little pony dripping snake oil'
    end

  end

  describe '#.decrypt(ciphertext_object)' do

    it 'returns the cleartext decrypted from the ciphertext_object with the instance cipher and key' do
      expect( subject.decrypt('My little pony dripping snake oil') ).to eq 'My little pony'
    end

  end

end
