require 'secret_store/base'
require 'secret_store/store_provider/memory'
require 'secret_store/test'

module SecretStore

  module Test

    module SecretStoreFactory

      def self.fabricate(namespace: nil, key: nil)
        store = StoreAPI.new(SecretStore::StoreProvider::Memory.new, namespace)
        cipher = CipherAPI.new(SecretStore::Test::SnakeOilCipherProvider, key)
        marshal = MarshalAPI.new(SecretStore::Test::RogueMarshalProvider)
        SecretStore::Base.new(store, cipher, marshal)
      end

    end

  end

end
