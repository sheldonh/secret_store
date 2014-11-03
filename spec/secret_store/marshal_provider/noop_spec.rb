require 'spec_helper'

require 'secret_store/marshal_provider/noop'

describe SecretStore::MarshalProvider::Noop do

  it 'is a module' do
    expect( described_class ).to be_a Module
  end

end
