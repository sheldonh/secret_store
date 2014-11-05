Given(/^a secret store$/) do
  @test.create_secret_store
end

When(/^the developer sets the secret$/) do
  @test.developer_sets_secret
end

Then(/^the secret ciphertext is in the store$/) do
  @test.secret_ciphertext_is_in_store
end

Then(/^the secret cleartext is not in the store$/) do
  @test.secret_cleartext_is_not_in_store
end

Then(/^the application gets the secret cleartext$/) do
  @test.application_gets_secret_cleartext
end
