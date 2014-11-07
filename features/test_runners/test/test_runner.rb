require 'rspec/matchers'

module SecretStore

  module TestRunner

    class Test
      include RSpec::Matchers

      def create_secret_store
        @store = SecretStore::Store.new(SecretStore::StoreProvider::Memory.new)
        @cipher = SecretStore::Store.new(SecretStore::CipherProvider::SnakeOil.new)
        @secret_store = SecretStore::Base.new(@store, @cipher)
      end

      def developer_sets_secret
        @secret_cleartext = 'The cake is a lie!'
        @secret_key = SecretStore::Key.new('password', '1')
        @secret_name = 'deep-dark-secret'
        @secret_namespace = 'starjuice:secret_store:test:v1'
        @secret_store.set_secret(@secret_namespace, @secret_name, @secret_key, @secret_cleartext)
      end

      def secret_ciphertext_is_in_store
        @secret_ciphertext = @secret_store.store.get(@secret_namespace, @secret_name)
        expect( @secret_ciphertext ).to match /dripping snake oil/
      end

      def secret_cleartext_is_not_in_store
        @secret_ciphertext = @secret_store.store.get(@secret_namespace, @secret_name)
        expect( @secret_ciphertext ).to_not eq @secret_cleartext
      end

      def application_gets_secret_cleartext
        @application_secret_store = SecretStore::Base.new(@store, @cipher)
        @application_secret_cleartext = @application_secret_store.get_secret(@secret_namespace, @secret_name, @secret_key)
        expect( @application_secret_cleartext ).to eq @secret_cleartext
      end
    end

  end

end
