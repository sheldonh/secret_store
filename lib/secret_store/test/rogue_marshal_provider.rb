module SecretStore

  module Test

    module RogueMarshalProvider

      def self.marshal(o)
        "Rogue " + o
      end

      def self.unmarshal(o)
        o.gsub(/^Rogue /, '')
      end

    end

  end

end
