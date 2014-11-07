Before('@manage_secrets') do
  @test = SecretStore::TestRunner::Test.new
end

Before('@use_secrets') do
  @test = SecretStore::TestRunner::Test.new
end
