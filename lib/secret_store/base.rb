require 'secret_store/cipher_api'
require 'secret_store/marshal_api'
require 'secret_store/store_api'

module SecretStore

  class Base

    def initialize(store, cipher, marshal)
      @store = store
      @cipher = cipher
      @marshal = marshal
    end

    def set_secret(secret_name, secret_value)
      ciphertext_object = @cipher.encrypt(secret_value)
      encoded_ciphertext = @marshal.marshal(ciphertext_object)
      @store.set(secret_name, encoded_ciphertext)
      nil
    end

    def get_secret(secret_name)
      # TODO up to here
    end

  end

end
