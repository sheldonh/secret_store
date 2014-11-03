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

end
