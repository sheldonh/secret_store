require 'spec_helper'

require 'secret_store/marshal_api'
require 'secret_store/test'

describe SecretStore::MarshalAPI do

  let(:provider) { SecretStore::Test::RogueMarshalProvider }
  subject { described_class.new(provider) }

  describe '.marshal(ciphertext_object)' do

    it 'returns a marshalled representation of the ciphertext_object' do
      expect( subject.marshal('unbreakable ciphertext') ).to eq 'Rogue unbreakable ciphertext'
    end

  end

  describe '.unmarshal(encoded_ciphertext)' do

    it 'returns the ciphertext_object represented by the encoded_ciphertext' do
      expect( subject.unmarshal('Rogue unbreakable ciphertext') ).to eq 'unbreakable ciphertext'
    end

  end

end
