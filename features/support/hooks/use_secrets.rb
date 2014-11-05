require_relative '../test_runners/stub_secret_store_test_runner'

Before('@use_secrets') do
  @test = SecretStore::Test::StubSecretStoreTestRunner.new
end
