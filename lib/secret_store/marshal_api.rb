module SecretStore

  class MarshalAPI

    def initialize(provider)
      @provider = provider
    end

    def marshal(ciphertext_object)
      @provider.marshal(ciphertext_object)
    end

    def unmarshal(encoded_ciphertext)
      @provider.unmarshal(encoded_ciphertext)
    end

  end

end
