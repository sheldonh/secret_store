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

  Scenario: Query secrets
    Given a secret store
    And the secret store includes secrets with strong encryption
    And the secret store includes secrets with weak encryption
    When the operator searches for the weak encryption type
    Then the operator gets just the secrets with weak encryption

  Scenario: Namespaces
    Given a secret store
    When two secrets with the same name are stored in two namespaces
    Then the two secrets can be fetched from the two namespaces
