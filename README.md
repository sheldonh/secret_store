# secure_secret_store

An experimental toolkit for storing secrets securely. It started in response to dockerized applications that need access to secrets.
Making secrets available in files is uncomfortable in a Docker cluster. So the idea, instead, is to configure applications with
the location of a secret store, the identity of their configs within that store and a key for decrypting those configs.

Initial stab uses redis. Others would need to follow.

## Testing

```
git clone git@github.com:sheldonh/secret_store.git
cd secret_store
rvm use .
bundle
rake test
```

## Ponderance

This whole marshalling thing feels like it's going to get horrible.

The reason I wanted marshalling flexibility was so that I could make trade offs, e.g.

* It is most important to me to be able to find all secrets created with a weak cipher (store as object or JSON string).
* It is most important to me that secrets be a single string that's safe to pass on the command-line (store base64 string).

I can now see that allowing ciphers to provide anything they want does not assist these goals.

So I think I should define what comes out of CipherAPI#encrypt. I'll provide a Cipherext class that ciphers can initialize with the ciphertext and metadata. The CipherText can communicate the labels, values and types of its composed values to the store, and the store can marshal as it sees fit.

Then there only needs to be one kind of marshal per trade off I want to make; whether I choose to base64-encode a metadata property or not is no concern of the store.

An implication is that you /must/ use the same marshalling discipline to unmarshal stored values as was used to marshal them when they were stored.

### Brain wave

Each Cipher must supply a CiphertextDefinition. Cipher#encrypt returns a Ciphertext object that
contains this definition, and Cipher#decrypt uses this definition to validate a given Ciphertext object. Marshalling can use the definition too.

* `cipher_id` - e.g. `aes-256-cbc`
* `key_id` - for easy key rotation, implementors that don't want to bother can just always use `"default"`
* `attributes` - set of label:type:value tuples that MUST exist in each Ciphertext; unexpected attributes are an error
  * e.g. `iv`, `salt`, `iterations`, `ciphertext` (hmmm, maybe call this components instead of attributes
* `metadata` - set of label:type:value tuples that MAY exist in each Ciphertext; unexpected attributes are ignored
  * e.g. `issued`, `expiry`

A Cipher would not set up metadata, but it could be attached by something else. Need a name for the something else. Annotator?
