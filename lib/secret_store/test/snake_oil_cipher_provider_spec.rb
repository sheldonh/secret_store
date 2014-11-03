require 'spec_helper'

require 'secret_store/test'

describe SecretStore::Test::SnakeOilCipherProvider do

  it 'is a module' do
    expect( described_class ).to be_a Module
  end

  describe '.encrypt(cleartext, key)' do

    it 'returns the cleartext with " dripping snake oil" appended to it' do
      expect( described_class.encrypt('My little pony', 'ignored-key') ).to eq 'My little pony dripping snake oil'
    end

  end

end
