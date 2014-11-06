require 'rspec/matchers'

module SecretStore
  class Key
    def initialize(data, identity)
    end
  end

  class Base
    attr_reader :store, :cipher

    def initialize(store, cipher)
      @store = store
      @cipher = cipher
    end

    def get_secret(namespace, name, key)
      'The cake is a lie!'
    end
  end

  module Test
    class StubSecretStore
      attr_reader :store, :cipher

      def initialize(store, cipher)
        @store = store
        @cipher = cipher
      end

      def set_secret(namespace, name, key, cleartext)
      end

      def get_secret(namespace, name, key)
        'The cake is a lie!'
      end
    end

    class StubStore
      def get(namespace, name)
        'The cake is a lie! dripping snake oil'
      end
    end

    class StubCipher
    end

    class StubSecretStoreTestRunner
      include RSpec::Matchers

      def create_secret_store
        @secret_store = SecretStore::Test::StubSecretStore.new(SecretStore::Test::StubStore.new, SecretStore::Test::StubCipher.new)
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
        @application_secret_store = SecretStore::Base.new(@secret_store.store, @secret_store.cipher)
        @application_secret_cleartext = @application_secret_store.get_secret(@secret_namespace, @secret_name, @secret_key)
        expect( @application_secret_cleartext ).to eq @secret_cleartext
      end
    end

  end
end
