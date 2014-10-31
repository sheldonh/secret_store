require 'spec_helper'

require 'secret_store'

class SecretStoreStubTestRunner
  def given_a_store
    @store = nil
  end

  def given_a_cipher
    @cipher = nil
  end

  def given_a_marshal
    @marshal = nil
  end

  def given_a_namespace
    @namespace = 'example-app:config:v1'
  end

  def given_a_key
    @key = 'password'
  end

  def given_a_secret_name
    @secret_name = 'deep-dark-secret'
  end

  def given_a_secret_cleartext
    @secret_cleartext = 'The cake is a lie!'
  end

  def developer_instantiates_a_secret_store
    #@secret_store = ...
  end

  def developer_sets_the_secret
    #@secret_store.set_secret(@secret_name, @secret_cleartext)
  end

  def secret_ciphertext_is_in_the_store
    # XXX Hmmmm... how am I going to do assertions in my test runners?
  end

  def secret_cleartext_is_not_in_the_store
  end

  def application_instantiates_a_secret_store
  end

  def application_gets_the_secret_cleartext
  end
end

describe SecretStore do

  let(:t) { SecretStoreStubTestRunner.new }

  context "As a developer" do
    context "In order to configure applications" do
      context "I want to securely store secrets for my apps to fetch" do

        # XXX each of these in an it?
        t.given_a_store
        t.given_a_cipher
        t.given_a_marshal
        t.given_a_namespace
        t.given_a_key
        t.given_a_secret_name
        t.given_a_secret_cleartext

        t.developer_instantiates_a_secret_store
        t.developer_sets_the_secret

        t.secret_ciphertext_is_in_the_store
        t.secret_cleartext_is_not_in_the_store

        t.application_instantiates_a_secret_store
        t.application_gets_the_secret_cleartext
      end
    end
  end

end
