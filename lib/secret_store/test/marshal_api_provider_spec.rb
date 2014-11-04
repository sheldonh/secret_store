require 'spec_helper'

require 'secret_store/marshal_api'

shared_examples 'a MarshalAPI provider' do |valid_ciphertext_objects|

  subject { SecretStore::MarshalAPI.new(described_class) }

  valid_ciphertext_objects.each do |label, (ciphertext_object, encoded_ciphertext)|

    describe ".marshal(ciphertext_object<#{label}>)" do

      it 'returns encoded ciphertext that unmarshals to the ciphertext_object' do
        expect( subject.unmarshal(subject.marshal(ciphertext_object)) ).to eq ciphertext_object
      end

      it 'raises a SecretStore::MarshalError for nil input' do
        expect { subject.marshal(nil) }.to raise_error SecretStore::MarshalError
      end

    end

    describe ".unmarshal(encoded_ciphertext<#{label}>)" do

      it 'returns a ciphertext object that marshals to the encoded_ciphertext' do
        expect( subject.marshal(subject.unmarshal(encoded_ciphertext)) ).to eq encoded_ciphertext
      end

      it 'raises a SecretStore::MarshalError for nil input' do
        expect { subject.unmarshal(nil) }.to raise_error SecretStore::MarshalError
      end

    end

  end

end

=begin
shared_examples 'a MarshalAPI provider' do |marshalling_examples|

  subject { SecretStore::MarshalAPI.new(described_class) }

  marshalling_examples.each do |label, (ciphertext_object, encoded_ciphertext)|

    describe ".marshal(ciphertext_object<#{label}>)" do

      it 'returns encoded ciphertext that unmarshals to the ciphertext_object' do
        expect( subject.unmarshal(subject.marshal(ciphertext_object)) ).to eq ciphertext_object
      end

    end

    describe ".unmarshal(encoded_ciphertext<#{label}>)" do

      it 'returns a ciphertext object that marshals to the encoded_ciphertext' do
        expect( subject.marshal(subject.unmarshal(encoded_ciphertext)) ).to eq encoded_ciphertext
      end

    end

  end

end
=end
