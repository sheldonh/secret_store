#!/usr/bin/env ruby

class SecureSecretStore
  def initialize(store, crypto, marshal)
    @store = store
    @crypto = crypto
    @marshal = marshal
  end

  def set_secret(secret_name, secret)
    encrypted_data = @marshal.marshal(@crypto.encrypt(secret))
    @store.set(secret_name, encrypted_data)
  end

  def get_secret(secret_name)
    encrypted_data = @marshal.unmarshal(@store.get(secret_name))
    @crypto.decrypt(encrypted_data)
  end

  def get_all_secrets
    @store.get_map.tap do |map|
      map.each do |k, v|
        crypts[k] = @crypto.decrypt(@marshal.unmarshal(v))
      end
    end
  end
end

class RedisStoreProvider
  def initialize(redis, key_prefix)
    @redis = redis
    @key_prefix = key_prefix
  end

  def set(key, value)
    @redis.set(prefixed_key(key), value)
    @redis.rpush(@key_prefix, key)
  end

  def get(key)
    @redis.get(prefixed_key(key))
  end

  def get_map
    keys = get_list(@key_prefix)
    {}.tap do |map|
      keys.each do |key|
        v = get(key)
        map[key] = v unless v.nil?
      end
    end
  end

  private

    def get_list(key)
      @redis.lrange(key, 0, -1)
    end

    def prefixed_key(key)
      @key_prefix + ":" + key
    end

end

require "openssl"
class Aes256CbcCryptoProvider

  ITERATIONS = 20_000 unless defined?(ITERATIONS)

  def initialize(encryption_key)
    @encryption_key = encryption_key
  end

  def encrypt(secret)
    Crypto::encrypt(@encryption_key, secret)
  end

  def decrypt(crypto)
    Crypto::decrypt(@encryption_key, crypto)
  end

  private

    module Crypto

      def self.encrypt(key, plaintext)
        cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
        cipher.encrypt
        iv = cipher.random_iv
        salt = Time.now.nsec.to_s
        iterations = ITERATIONS
        cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iterations, cipher.key_len)
        ciphertext = cipher.update(plaintext) + cipher.final
        {iv: iv, salt: salt, iterations: iterations, ciphertext: ciphertext}
      end

      def self.decrypt(key, crypto)
        ciphertext, iv, salt, iterations = crypto[:ciphertext], crypto[:iv], crypto[:salt], crypto[:iterations]
        cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
        cipher.decrypt
        cipher.iv = iv
        cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, iterations, cipher.key_len)
        plaintext = cipher.update(ciphertext) + cipher.final
      end

    end

end

class Aes256CbcJsonMapMarshal
  def initialize
    @marshal = JsonMapMarshal.new(:iv => :base64, :salt => :base64, :iterations => :literal, :ciphertext => :base64)
  end

  def marshal(map)
    @marshal.marshal(map)
  end

  def unmarshal(string)
    @marshal.unmarshal(string)
  end
end

require 'base64'
require 'json'
class JsonMapMarshal
  def initialize(fields = {})
    @fields = fields
  end

  def marshal(map)
    marshalled = {}
    map.each do |k, v|
      marshalled[k] = case @fields[k]
                   when :base64
                     Base64::encode64(v).chomp!
                   when :literal
                     v
                   else
                     raise "can't marshal #{k} as field type #{@fields[k]}"
                   end
    end
    marshalled.to_json
  end

  def unmarshal(string)
    JSON.parse(string).tap do |map|
      @fields.each do |f, type|
        v = map.delete(f.to_s)
        map[f] = case type
                 when :base64
                   Base64::decode64(v)
                 when :literal
                   v
                 else
                   raise "can't unmarshal #{k} as field type #{@fields[k]}"
                 end
      end
    end
  end
end

if __FILE__ == $0
  require 'redis'
  redis = Redis.new
  store = RedisStoreProvider.new(redis, 'example-app:config:v1')
  crypto = Aes256CbcCryptoProvider.new('password')
  marshal = Aes256CbcJsonMapMarshal.new
  secrets = SecureSecretStore.new(store, crypto, marshal)

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
