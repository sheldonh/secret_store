require 'secret_store/test'
require 'rspec/matchers'

class StubSecretStoreTestRunner
  include RSpec::Matchers

  def create_secret_store
    @secret_store = SecretStore::Test::SecretStoreFactory.fabricate(namespace: 'starjuice:secret_store:test:v1', key: 'password')
  end

  def developer_sets_secret
    @secret_name = 'deep-dark-secret'
    @secret_cleartext = 'The cake is a lie!'
    @secret_store.set_secret(@secret_name, @secret_cleartext)
  end

  def secret_ciphertext_is_in_store
    @secret_ciphertext = @secret_store.store.get(@secret_name)
    expect( @secret_ciphertext ).to match /dripping snake oil/
  end

  def secret_cleartext_is_not_in_store
    @secret_ciphertext = @secret_store.store.get(@secret_name)
    expect( @secret_ciphertext ).to_not eq @secret_cleartext
  end

  def application_gets_secret_cleartext
    @application_secret_store = SecretStore::Base.new(@secret_store.store, @secret_store.cipher, @secret_store.marshal)
    @application_secret_cleartext = @application_secret_store.get_secret(@secret_name)
    expect( @application_secret_cleartext ).to eq @secret_cleartext
  end
end
