# secure_secret_store

An experimental toolkit for storing secrets securely. It started in response to dockerized applications that need access to secrets.
Making secrets available in files is uncomfortable in a Docker cluster. So the idea, instead, is to configure applications with
the location of a secret store, the identity of their configs within that store and a key for decrypting those configs.

Initial stab uses redis. Others would need to follow.
