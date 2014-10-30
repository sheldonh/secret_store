#!/usr/bin/env ruby

class SecretStore
  def initialize(store, cipher, marshal)
    @store = store
    @cipher = cipher
    @marshal = marshal
  end

  def set_secret(secret_name, secret)
    ciphertext_object = @cipher.encrypt(secret)
    encoded_ciphertext = @marshal.marshal(ciphertext_object)
    @store.set(secret_name, encoded_ciphertext)
  end

  def get_secret(secret_name)
    encoded_ciphertext = @store.get(secret_name)
    ciphertext_object = @marshal.unmarshal(encoded_ciphertext)
    @cipher.decrypt(ciphertext_object)
  end

  def get_all_secrets
    @store.all.tap do |map|
      map.each do |secret_name, encoded_ciphertext|
        ciphertext_object = @marshal.unmarshal(encoded_ciphertext)
        crypts[secret_name] = @cipher.decrypt(ciphertext_object)
      end
    end
  end
end

class StoreProviderAPI
  def initialize(store, object)
    @store = store
    @object = object
  end

  def set(property, value)
    @store.set(@object, property, value)
  end

  def get(property)
    @store.get(@object, property)
  end

  def all
    @store.all(@object)
  end
end

class RedisStoreProvider
  def initialize(redis)
    @redis = redis
  end

  def set(prefix, key, value)
    @redis.set(compound_key(prefix, key), value)
    @redis.rpush(prefix, key)
  end

  def get(prefix, key)
    @redis.get(compound_key(prefix, key))
  end

  def all(prefix)
    keys = @redis.lrange(prefix, 0, -1)
    {}.tap do |map|
      keys.each do |key|
        v = get(key)
        map[key] = v unless v.nil?
      end
    end
  end

  private

    def compound_key(prefix, key)
      prefix + ":" + key
    end
end

class CipherProviderAPI
  def initialize(provider, key)
    @provider = provider
    @key = key
  end

  def encrypt(cleartext)
    @provider.encrypt(@key, cleartext)
  end

  def decrypt(ciphertext_object)
    @provider.decrypt(@key, ciphertext_object)
  end
end

require "openssl"
module Aes256CbcCipherProvider

  ITERATIONS = 20_000 unless defined?(ITERATIONS)

  def self.encrypt(key, cleartext)
    cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
    cipher.encrypt
    iv = cipher.random_iv
    salt = Time.now.nsec.to_s
    iterations = ITERATIONS
    cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iterations, cipher.key_len)
    ciphertext = cipher.update(cleartext) + cipher.final
    ciphertext_object = {iv: iv, salt: salt, iterations: iterations, ciphertext: ciphertext}
  end

  def self.decrypt(key, ciphertext_object)
    ciphertext, iv, salt, iterations = ciphertext_object[:ciphertext], ciphertext_object[:iv], ciphertext_object[:salt], ciphertext_object[:iterations]
    cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
    cipher.decrypt
    cipher.iv = iv
    cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iterations, cipher.key_len)
    cleartext = cipher.update(ciphertext) + cipher.final
  end
end

class CipherMarshalAPI
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

require 'base64'
require 'json'
class JsonBase64MapMarshal

  def initialize(fields = {})
    @fields = fields
  end

  def marshal(map)
    marshalled = {}
    map.each do |k, v|
      type = @fields[k]
      raise "refusing to marshal unexpected property '#{k}'" if type.nil?
      marshalled[k] = type == :base64 ? Base64::encode64(v).chomp! : v
    end
    marshalled.to_json
  end

  def unmarshal(string)
    JSON.parse(string).inject({}) do |acc, (k, v)|
      ksym, type = @fields.detect { |f, t| f.to_s == k }
      raise "refusing to unmarshal unexpected property '#{k}'" if ksym.nil?
      acc[ksym] = type == :base64 ? Base64::decode64(v) : v
      acc
    end
  end

end

if __FILE__ == $0
  require 'redis'
  redis = Redis.new
  store_provider = RedisStoreProvider.new(redis)
  store = StoreProviderAPI.new(store_provider, 'example-app:config:v1')
  cipher_provider = Aes256CbcCipherProvider
  cipher = CipherProviderAPI.new(cipher_provider, 'password')
  marshal_provider = JsonBase64MapMarshal.new(:iv => :base64, :salt => :base64, :iterations => :number, :ciphertext => :base64)
  marshal = CipherMarshalAPI.new(marshal_provider)
  secrets = SecretStore.new(store, cipher, marshal)

  secrets.set_secret('deep-dark-secret', 'The cake is a lie!')
  secrets.set_secret('light-blue-secret', 'The sky is not really blue.')
  secrets.set_secret('bright-pink-secret', "It's not rock, it's pop!")

  puts redis.get('example-app:config:v1:deep-dark-secret')
  puts "=> " + secrets.get_secret('deep-dark-secret')
  puts redis.get('example-app:config:v1:light-blue-secret')
  puts "=> " + secrets.get_secret('light-blue-secret')
  puts redis.get('example-app:config:v1:bright-pink-secret')
  puts "=> " + secrets.get_secret('bright-pink-secret')
end
