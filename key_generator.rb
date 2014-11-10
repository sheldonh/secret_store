require 'openssl'

module CMS

  class ContentInfo
    attr_reader :content_type, :content

    def initialize(content_type: nil, content: nil)
      @content_type = content_type
      @content = content
    end

    def to_asn1
      OpenSSL::ASN1::Sequence.new( [@content_type, @content ].map(&:to_asn1) )
    end
  end

  class EncryptedData
    attr_reader :version, :encrypted_content_info

    def initialize(version: nil, encrypted_content_info: nil)
      @version = version
      @encrypted_content_info = encrypted_content_info
    end

    def to_asn1
      OpenSSL::ASN1::Sequence.new( [@version, @encrypted_content_info].map(&:to_asn1) )
    end
  end

  class EncryptedContentInfo
    attr_reader :content_type, :content_encryption_algorithm, :encrypted_content

    def initialize(content_type: nil, content_encryption_algorithm: nil, encrypted_content: nil)
      @content_type = content_type
      @content_encryption_algorithm = content_encryption_algorithm
      @encrypted_content = encrypted_content
    end

    def to_asn1
      OpenSSL::ASN1::Sequence.new( [@content_type, @content_encryption_algorithm, @encrypted_content].map(&:to_asn1) )
    end
  end

  class AlgorithmIdentifier
    attr_reader :algorithm, :parameters

    def initialize(algorithm: nil, parameters: nil)
      @algorithm = algorithm
      @parameters = parameters
    end

    def to_asn1
      OpenSSL::ASN1::Sequence.new( [@algorithm, @parameters].map(&:to_asn1) )
    end

  end

  class NilClass
    def to_asn1
      OpenSSL::ASN1::Null.new
    end
  end

  class Version
    attr_reader :value

    def initialize(value)
      @value = value
    end

    def to_asn1
      OpenSSL::ASN1::Integer.new(@value)
    end
  end

  class OID
    attr_reader :asn1, :dotted, :label

    def initialize(asn1, short_name, long_name)
      @asn1 = asn1
      @dotted = asn1.scan(/((?<![\d._-])\d+(?![\d._-]))/).join('.')
      @short_name = short_name
      @long_name = long_name
    end

    def to_asn1
      OpenSSL::ASN1::ObjectId.new(@dotted)
    end
  end

  class OctetString
    attr_reader :value

    def initialize(value)
      @value = value
    end

    def to_asn1
      OpenSSL::ASN1::OctetString.new(@value)
    end
  end

  module ContentType

    module EncryptedData
      def self.to_asn1
        CMS::OID.new('{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) encryptedData(6)}', 'encryptedData', 'encryptedData').to_asn1
      end
    end

    module Data
      def self.to_asn1
        CMS::OID.new('{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) data(1)}', 'data', 'data').to_asn1
      end
    end

  end

end
module SecretStore

  module CipherProvider

    class ContentEncryptionAlgorithm
      def initialize(algorithm, params)
        @algorithm = algorithm
        @params = params
      end
    end

    class EncryptedContentInfo
      def initialize(algorithm, encrypted_content)
        @algorithm = algorithm
        @encrypted_content = encrypted_content
      end
    end

    module Aes256CbcCipherProvider

      def self.generate_key
        cipher = new_cipher
        cipher.encrypt
        cipher.random_key
      end

      def self.encrypt(cleartext, cek)
        cipher = new_cipher
        cipher.encrypt
        cipher.key = cek
        iv = cipher.random_iv
        cipher.update(cleartext)
        ciphertext = cipher.final
        CMS::ContentInfo.new(
          content_type: CMS::ContentType::EncryptedData,
          content: CMS::EncryptedData.new(
            version: CMS::Version.new(0),
            encrypted_content_info: CMS::EncryptedContentInfo.new(
              content_type: CMS::ContentType::Data,
              content_encryption_algorithm: CMS::AlgorithmIdentifier.new(
                algorithm: CMS::OID.new('{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) aes(1) aes256-CBC(42)}', 'aes256-CBC', 'aes256-CBC'),
                parameters: CMS::OctetString.new(iv)
              ),
              encrypted_content: CMS::OctetString.new(ciphertext)
            )
          )
        )
      end

      def self.decrypt(content_info, cek)
        p content_info
        iv = content_info.content.encrypted_content_info.content_encryption_algorithm.parameters.value
        encrypted_content = content_info.content.encrypted_content_info.encrypted_content.value

        cipher = new_cipher
        cipher.decrypt
        cipher.key = cek
        cipher.iv = iv
        cipher.update(encrypted_content)
        cipher.final
      end

      private

        def self.new_cipher
          cipher = OpenSSL::Cipher::AES256.new(:CBC)
        end

    end

  end

  module Encoding

    module Key

      def to_hex(key)
        key.unpack('H*').first
      end

      def from_hex(hex)
        hex.scan(/../).map { |x| x.hex }.pack('c*')
      end

    end

  end

end

if $0 == __FILE__
  require 'base64'
  include Base64
  include SecretStore::Encoding::Key

  key = SecretStore::CipherProvider::Aes256CbcCipherProvider.generate_key
  puts "#{key.size * 8} bits"
  puts to_hex(key)
  puts to_hex(from_hex(to_hex(key)))
  puts encode64(key)

  plaintext = "The cake is a lie!"
  encrypted = SecretStore::CipherProvider::Aes256CbcCipherProvider.encrypt(plaintext, key)
  asn1 = encrypted.to_asn1
  puts "ASN1: (hi ascii garbage): #{asn1.to_der}"
  puts "ASN1: (base64) #{encode64 asn1.to_der}"
  decrypted = SecretStore::CipherProvider::Aes256CbcCipherProvider.decrypt(encrypted, key)
  puts "DECRYPTED: #{decrypted}"

end
