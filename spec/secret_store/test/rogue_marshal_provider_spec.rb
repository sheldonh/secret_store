require 'spec_helper'

require 'secret_store/test'

describe SecretStore::Test::RogueMarshalProvider do

  it_behaves_like "a MarshalAPI provider", string: ['unbreakable ciphertext', 'Rogue unbreakable ciphertext']

  describe '.marshal(ciphertext_object)' do

    it 'returns the ciphertext_object with "Rogue " prepended to it' do
      expect( described_class.marshal('unbreakable ciphertext') ).to eq 'Rogue unbreakable ciphertext'
    end

  end

  describe '.unmarshal(encoded_ciphertext)' do

    it 'returns the encoded_ciphertext with "Rogue " stripped from the front' do
      expect( described_class.unmarshal('Rogue unbreakable ciphertext') ).to eq 'unbreakable ciphertext'
    end

  end

end
