module SecretStore

  class StoreAPI

    def initialize(provider, namespace)
      @provider = provider
      @namespace = namespace
    end

    def set(property, value)
      @provider.set(@namespace, property, value)
    end

    def get(property)
      @provider.get(@namespace, property)
    end

  end

end
