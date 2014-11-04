module SecretStore

  class CipherAPI

    def initialize(cipher, key)
      @cipher = cipher
      @key = key
    end

    def encrypt(cleartext)
      @cipher.encrypt(cleartext, @key)
    end

    def decrypt(ciphertext_object)
      @cipher.decrypt(ciphertext_object, @key)
    end

  end

end
