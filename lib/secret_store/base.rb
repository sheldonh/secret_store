require 'secret_store/cipher_api'
require 'secret_store/marshal_api'
require 'secret_store/store_api'

module SecretStore

  class Base

    attr_reader :store, :cipher, :marshal

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
      encoded_ciphertext = @store.get(secret_name)
      unless encoded_ciphertext.nil?
        ciphertext_object = @marshal.unmarshal(encoded_ciphertext)
        @cipher.decrypt(ciphertext_object)
      end
    end

  end

end
