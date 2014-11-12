require 'openssl'
require 'base64'
require 'json'
require 'yaml'

class NilClass
  def to_asn1
    OpenSSL::ASN1::Null.new(nil)
  end

  def to_json
    "null"
  end
end

module CMS

  class ContentInfo
    attr_reader :content_type, :content

    def initialize(content_type: nil, content: nil)
      @content_type = content_type
      @content = content
    end

    def to_asn1
      ct = @content_type.to_asn1
      c = @content.to_asn1

      OpenSSL::ASN1::Sequence.new( [ct, c] )
      #OpenSSL::ASN1::Sequence.new( [@content_type, @content ].map(&:to_asn1) )
    end

    def to_json
      %Q<{"contentType":#{@content_type.to_json},"content":#{@content.to_json}}>
    end
  end

  class EncryptedData
    attr_reader :version, :encrypted_content_info, :unprotected_attrs

    def initialize(version: nil, encrypted_content_info: nil, unprotected_attrs: nil)
      @version = version
      @encrypted_content_info = encrypted_content_info
      @unprotected_attrs = unprotected_attrs
    end

    def to_asn1(*args)
      OpenSSL::ASN1::ASN1Data.new(
        [OpenSSL::ASN1::Sequence.new( [@version, @encrypted_content_info, @unprotected_attrs].map(&:to_asn1) )],
        0, :CONTEXT_SPECIFIC
      )
    end

    def to_json
      %Q<{"version":#{@version.to_json},"encryptedContentInfo":#{@encrypted_content_info.to_json},"unprotectedAttrs":#{@unprotected_attrs.to_json}}>
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

    def to_json
      %Q<{"contentType":#{@content_type.to_json},"contentEncryptionAlgorithm":#{@content_encryption_algorithm.to_json},"encryptedContent":#{@encrypted_content.to_json}}>
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

    def to_json
      %Q<{"algorithm":#{@algorithm.to_json},"parameters":#{@parameters.to_json}}>
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

    def to_json
      @value.to_json
    end
  end

  class OID
    # nanf - NameAndNumberForm, e.g. {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) md2WithRSAEncryption(2)}
    # dotted - ObjIdComponentsList, e.g. 1.2.840.113549.1.1.2
    # short_name - NameForm, e.g. RSA-MD2
    # long_name - NameForm, e.g. md2WithRSAEncryption
    #
    # See ITU-T Rec. X.680 http://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.680-200811-I!!PDF-E&type=items
    attr_reader :nanf, :dotted, :label

    def initialize(nanf, short_name, long_name)
      @nanf = nanf
      @dotted = nanf.scan(/((?<![\d._-])\d+(?![\d._-]))/).join('.')
      @short_name = short_name
      @long_name = long_name
    end

    def to_asn1
      OpenSSL::ASN1::ObjectId.new(@dotted)
    end

    def to_json
      %Q<{"nanf":#{@nanf.to_json},"dotted":#{@dotted.to_json},"shortName":#{@short_name.to_json},"longName":#{@long_name.to_json}>
    end
  end

  class OctetString
    attr_reader :value

    include Base64

    def initialize(value)
      @value = value
    end

    def to_asn1
      OpenSSL::ASN1::OctetString.new(@value)
    end

    def to_json
      %Q<{"#{strict_encode64(@value)}"}>
    end
  end

  class BinaryString < OctetString
  end

  class CharacterString < BinaryString
    def to_json
      @value.to_json
    end
  end

  module ContentType

    module EncryptedData
      def self.oid
        CMS::OID.new('{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) encryptedData(6)}', 'encryptedData', 'encryptedData')
      end

      def self.to_asn1
        oid.to_asn1
      end

      def self.to_json
        oid.to_json
      end
    end

    module Data
      def self.oid
        CMS::OID.new('{iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7) data(1)}', 'data', 'data')
      end

      def self.to_asn1
        oid.to_asn1
      end

      def self.to_json
        oid.to_json
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
        ciphertext = cipher.update(cleartext) + cipher.final

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
        iv = content_info.content.encrypted_content_info.content_encryption_algorithm.parameters.value
        encrypted_content = content_info.content.encrypted_content_info.encrypted_content.value

        cipher = new_cipher
        cipher.decrypt
        cipher.key = cek
        cipher.iv = iv
        cipher.update(encrypted_content) + cipher.final
      end

      private

        def self.new_cipher
          cipher = OpenSSL::Cipher::AES256.new(:CBC)
        end

    end

  end

  module Encoding

    def to_hex(key)
      key.unpack('H*').first
    end

    def from_hex(hex)
      hex.scan(/../).map { |x| x.hex }.pack('c*')
    end

  end

end

if $0 == __FILE__
  require 'base64'
  include Base64
  include SecretStore::Encoding

  plaintext = "The cake is a lie!"
  puts "PLAINTEXT: #{plaintext}"
  key = SecretStore::CipherProvider::Aes256CbcCipherProvider.generate_key

  puts
  puts "KEY:"
  puts "#{key.size * 8} bits"
  puts "Hex: #{to_hex(from_hex(to_hex(key)))}"
  puts "Base64: #{strict_encode64(key)}"

  encrypted_data = SecretStore::CipherProvider::Aes256CbcCipherProvider.encrypt(plaintext, key)

  File.open("encrypted_data.der", "w") do |io|
    io.write encrypted_data.to_asn1.to_der
  end

  puts
  puts "IV: #{to_hex(encrypted_data.content.encrypted_content_info.content_encryption_algorithm.parameters.value)}"

  asn1 = encrypted_data.to_asn1
  puts
  puts "ASN1 (hi ascii garbage):\n#{asn1.to_der}"
  puts
  puts "ASN1 (base64):\n#{strict_encode64 asn1.to_der}"
  puts
  puts "JSON:\n#{encrypted_data.to_json}"

  puts
  puts asn1.to_yaml

  decrypted = SecretStore::CipherProvider::Aes256CbcCipherProvider.decrypt(encrypted_data, key)
  puts
  puts "DECRYPTED: #{decrypted}"

end
