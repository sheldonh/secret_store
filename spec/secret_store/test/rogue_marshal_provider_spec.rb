require 'spec_helper'

require 'secret_store/test'

describe SecretStore::Test::RogueMarshalProvider do

  describe '.marshal(ciphertext_object)' do

    it 'returns the ciphertext_object with "Rogue " prepended to it' do
      expect( described_class.marshal('unbreakable ciphertext') ).to eq 'Rogue unbreakable ciphertext'
    end

  end

end
