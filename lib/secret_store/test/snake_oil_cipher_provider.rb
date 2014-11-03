module SecretStore

  module Test

    module SnakeOilCipherProvider

      def self.encrypt(cleartext, key)
        cleartext + ' dripping snake oil'
      end

    end

  end

end
