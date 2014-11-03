module SecretStore

  module StoreProvider

    class Memory

      def initialize(initial = {})
        @memory = initial
      end

      def set(namespace, property, value)
        @memory[namespace] ||= {}
        @memory[namespace][property] = value
      end

      def get(namespace, property)
        @memory[namespace][property] if @memory.has_key?(namespace)
      end

    end

  end

end
