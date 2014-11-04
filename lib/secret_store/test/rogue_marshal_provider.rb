module SecretStore

  module Test

    module RogueMarshalProvider

      def self.marshal(o)
        raise SecretStore::MarshalError.new("can't marshal input of type #{o.class}") unless o.is_a?(String)
        "Rogue " + o
      end

      def self.unmarshal(o)
        raise SecretStore::MarshalError.new("can't unmarshal input of type #{o.class}") unless o.is_a?(String)
        o.gsub(/^Rogue /, '')
      end

    end

  end

end
