#!/usr/bin/env ruby

class SecretStore
  attr_reader :store, :cipher, :marshal

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

  def self.fabricate(namespace: nil, key: nil, store_provider: nil, cipher_provider: nil, marshal_provider: nil)
    store = StoreAPI.new(store_provider, namespace)
    marshal = MarshalAPI.new(marshal_provider)
    cipher = CipherAPI.new(cipher_provider, key)
    SecretStore.new(store, cipher, marshal)
  end
end

class StoreAPI
  def initialize(store, namespace)
    @store = store
    @namespace = namespace
  end

  def set(property, value)
    @store.set(@namespace, property, value)
  end

  def get(property)
    @store.get(@namespace, property)
  end

  def all
    @store.all(@namespace)
  end
end

class MemoryStoreProvider
  def initialize(initial_secrets = {})
    @secrets = Marshal.load(Marshal.dump(initial_secrets))
  end

  def set(namespace, key, value)
    @secrets[namespace] ||= {}
    @secrets[namespace][key] = value
  end

  def get(namespace, key)
    @secrets[namespace][key] if @secrets.has_key?(namespace)
  end

  def all(namespace)
    @secrets.has_key?(namespace) ? @secrets[namespace] : {}
  end
end

class RedisStoreProvider
  def initialize(redis)
    @redis = redis
  end

  def set(namespace, key, value)
    @redis.set(compound_key(namespace, key), value)
    @redis.rpush(namespace, key)
  end

  def get(namespace, key)
    @redis.get(compound_key(namespace, key))
  end

  def all(namespace)
    keys = @redis.lrange(namespace, 0, -1)
    {}.tap do |map|
      keys.each do |key|
        v = get(key)
        map[key] = v unless v.nil?
      end
    end
  end

  private

    def compound_key(namespace, key)
      namespace + ":" + key
    end
end

class CipherAPI
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

module SnakeOilCipherProvider
  def self.encrypt(key, cleartext)
    ciphertext_object = "#{cleartext} covered in snake oil"
  end

  def self.decrypt(key, ciphertext_object)
    ciphertext_object =~ /^(.*) covered in snake oil/
    cleartext = $1 ? $1 : (raise "unexpected decryption error")
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

module NoopMarshalProvider
  def self.marshal(o)
    o
  end

  def self.unmarshal(o)
    o
  end
end

require 'base64'
require 'json'
class JsonBase64MapMarshalProvider
  def initialize(fields = {})
    @fields = fields
  end

  def marshal(map)
    marshalled = {}
    map.each do |k, v|
      type = @fields[k]
      raise "refusing to marshal unexpected property '#{k}'" if type.nil?
      marshalled[k] = type == :base64 ? Base64::strict_encode64(v) : v
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

require 'base64'
module Base64MarshalProvider
  def self.marshal(o)
    Base64::strict_encode64(Marshal.dump(o))
  end

  def self.unmarshal(string)
    Marshal.load(Base64::decode64(string))
  end
end

module TestSecretStoreFactory
  def self.fabricate(namespace: nil, key: nil)
    SecretStore.fabricate(
      namespace: namespace,
      key: key,
      store_provider: MemoryStoreProvider.new,
      cipher_provider: SnakeOilCipherProvider,
      marshal_provider: NoopMarshalProvider)
  end
end

if __FILE__ == $0
  cipher_provider = Aes256CbcCipherProvider

  # The cipher provider and store provider might not make compatible encoding demands. For example, Aes256CbcCipherProvider
  # demands an object whose values are binary data, but RedisStoreProvider demands JSON objects.

  # So for base64-valued json marshalling into redis, we could use:
  require 'redis'
  redis = Redis.new
  store_provider = RedisStoreProvider.new(redis)
  marshal_provider = JsonBase64MapMarshalProvider.new(:iv => :base64, :salt => :base64, :iterations => :number, :ciphertext => :base64)

  ## If we didn't care about the readability of the data, we could use the simpler, stdlib-native Base64MarshalProvider:
  #marshal_provider = Base64MarshalProvider

  ## Or, for an unmarshalled in-memory store, we could have used:
  #store_provider = MemoryStoreProvider.new
  #marshal_provider = NoopMarshalProvider

  namespace = 'example-app:config:v1'
  secrets = SecretStore.fabricate(
    namespace: 'example-app:config:v1',
    key: 'password',
    store_provider: store_provider,
    cipher_provider: cipher_provider,
    marshal_provider: marshal_provider)

  ## For testing, there's a store that isn't secure at all; it just adds " covered in snake oil" to the plaintext.
  #secrets = TestSecretStoreFactory.fabricate(namespace: 'example-app:config:v1', key: 'password')

  secrets.set_secret('deep-dark-secret', 'The cake is a lie!')
  secrets.set_secret('light-blue-secret', 'The sky is not really blue.')
  secrets.set_secret('bright-pink-secret', "It's not rock, it's pop!")

  puts "Ciphertext:   " + secrets.store.get('deep-dark-secret')
  puts "=> Cleartext: " + secrets.get_secret('deep-dark-secret')
  puts "Ciphertext:   " + secrets.store.get('light-blue-secret')
  puts "=> Cleartext: " + secrets.get_secret('light-blue-secret')
  puts "Ciphertext:   " + secrets.store.get('bright-pink-secret')
  puts "=> Cleartext: " + secrets.get_secret('bright-pink-secret')
end
