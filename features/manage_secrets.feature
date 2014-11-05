Feature: Secret store
  As a security officer
  I want to manage stored secrets
  In order to respond to weak and exposed secrets

  Scenario: Find weak secrets
    Given a secret store
    And some secrets with weak encryption
    And some secrets with strong encryption
    When I search for weak encryption
    Then I just get the secrets with weak encryption
