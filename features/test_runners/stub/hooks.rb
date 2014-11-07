Before('@manage_secrets') do
  @test = SecretStore::TestRunner::Stub.new
end

Before('@use_secrets') do
  @test = SecretStore::TestRunner::Stub.new
end
