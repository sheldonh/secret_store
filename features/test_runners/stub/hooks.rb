Before('@manage_secrets') do
  @test = SecretStore::Test::StubSecretStoreTestRunner.new
end

Before('@use_secrets') do
  @test = SecretStore::Test::StubSecretStoreTestRunner.new
end
