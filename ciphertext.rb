#!/usr/bin/env ruby

class Ciphertext
  attr_reader :cipher_id, :key_id

  def initialize(cipher_id, key_id, attributes)
    @cipher_id = cipher_id
    @key_id = key_id
    @attributes = attributes
  end

  def set_attribute(label, type, value)
    @attributes[label] = {:type => type, :value => value}
  end

  def each_attribute
    @attributes.each do |label, attribute|
      yield label, attribute[:type], attribute[:value]
    end
  end

  def to_h
    {
      "cipher_id"  => @cipher_id,
      "key_id"     => @key_id,
      "attributes" => @properties.inject({}) do |acc, (label, attribute)|
        acc[label.to_s] = {
          "type"  => attribute[:type].to_s,
          "value" => case attribute[:type].to_s
                     when :string
                       attribute[:value]
                     when :int
                       attribute[:value].to_i
                     when :float
                       attribute[:value].to_f
                     else
                       raise "WTF"
                     end
        }
        acc
      end
    }
  end

  def from_h(h)
    h = h.dup
    cipher_id = h.delete("cipher_id") or raise "WTF"
    key_id = h.delete("key_id") or raise "WTF"
    attributes = h.inject({}) do |acc, (label, attribute)|
      acc[label] = {
        :type  => attribute["type"],
        :value => case attribute["value"]
                  when :string
                    attribute["value"]
                  when :int
                    attribute["value"].to_i
                  when :float
                    attribute["value"].to_f
                  else
                    raise "WTF"
                  end
      }
      acc
    end
    self.new(cipher_id, key_id, attributes)
  end
end

if $0 == __FILE__
  require 'yaml'
  puts Ciphertext.new('aes-256-cbc', 'my-secret-key-1', {iv: {type: :string}, 
end
