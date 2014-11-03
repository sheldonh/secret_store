module SecretStore

  module Test

    module RogueMarshalProvider

      def self.marshal(o)
        "Rogue " + o
      end

    end

  end

end
