Feature: Secret store
  As a developer
  I want to securely store secrets
  In order to configure applications

  Scenario: Set a secret
    Given a secret store
    When the developer sets the secret
    Then the secret ciphertext is in the store
    And the secret cleartext is not in the store
    And the application gets the secret cleartext
