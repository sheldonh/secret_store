module SecretStore

  module Test

    module SnakeOilCipherProvider

      def self.encrypt(cleartext, key)
        cleartext + ' dripping snake oil'
      end

      def self.decrypt(ciphertext_object, key)
        ciphertext_object.gsub(/ dripping snake oil/, '')
      end

    end

  end

end
