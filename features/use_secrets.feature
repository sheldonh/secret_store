@use_secrets
Feature: Use secrets
  As a developer
  I want to securely store secrets
  In order to configure applications

  Scenario: Set and get a secret
    Given a secret store
    When the developer sets the secret
    Then the secret ciphertext is in the store
    And the secret cleartext is not in the store
    And the application gets the secret cleartext

  Scenario: Namespaces
    Given a secret store
    When two secrets with the same name are stored in two namespaces
    Then the two secrets can be fetched from the two namespaces
