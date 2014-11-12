require 'openssl'

cleartext = "The cake is a lie!"

cipher = OpenSSL::Cipher::AES256.new(:CBC)
cipher.encrypt
cipher.random_key
iv = cipher.random_iv
ciphertext = cipher.update(cleartext) + cipher.final

cms = OpenSSL::ASN1::Sequence.new([
  OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.7.6"),
  OpenSSL::ASN1::Sequence.new([
    OpenSSL::ASN1::Integer.new(0),
    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.7.1"),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new("2.16.840.1.101.3.4.1.42"),
        OpenSSL::ASN1::OctetString.new(iv)
      ]),
      OpenSSL::ASN1::OctetString.new(ciphertext, 0, :IMPLICIT)
    ]),
    OpenSSL::ASN1::Set.new([], 1, :IMPLICIT)
  ], 0, :EXPLICIT)
])

$stdout.write cms.to_der
