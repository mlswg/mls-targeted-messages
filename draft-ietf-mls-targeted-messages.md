---
title: "Messaging Layer Security (MLS) Targeted Messages"
category: std

docname: draft-ietf-mls-targeted-messages-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - MLS
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "mlswg/mls-targeted-messages"
  latest: "https://mlswg.github.io/mls-targeted-messages/draft-ietf-mls-targeted-messages.html"

author:
 -
    fullname: Raphael Robert
    organization: Phoenix R&D GmbH
    email: ietf@raphaelrobert.com

normative:

...

--- abstract

This document defines targeted messages for the Messaging Layer Security
(MLS) protocol. A targeted message allows a member of an MLS group to
send an encrypted and authenticated message to another member of the same
group without creating a new group. The mechanism reuses Hybrid Public Key
Encryption (HPKE) and the MLS key schedule to provide confidentiality,
authentication, and binding to the group state.


--- middle

# Introduction

MLS application messages make sending encrypted messages to all group members
easy and efficient. Sometimes application protocols require that a group member
sends a message only to specific members of the same group, either for privacy
or for efficiency reasons.

Targeted messages are a way to achieve this without having to create a new group
with the sender and the specific recipients, which might not be possible or
desired. Instead, this document defines the format and encryption of a message
that is sent from a member of an existing group to another member of that group.

The goal is to provide a one-shot messaging mechanism offering confidentiality
and authentication, reusing mechanisms from {{!RFC9420}} and {{!RFC9180}}.
Targeted messages can be used as a building block for more complex messaging
protocols.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Format

This document defines the `mls_targeted_message` WireFormat, where the content
is a `TargetedMessage`.

A `TargetedMessage` is carried in the `MLSMessage` envelope defined in
{{Section 6 of !RFC9420}}:

~~~ tls
case mls_targeted_message:
    TargetedMessage targeted_message;
~~~

~~~ tls
struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
  opaque authenticated_data<V>;
  opaque encrypted_sender_auth_data<V>;
  opaque ciphertext<V>;
} TargetedMessage;

struct {
  uint32 sender_leaf_index;
  opaque signature<V>;
  opaque kem_output<V>;
} TargetedMessageSenderAuthData;

struct {
  ProtocolVersion version = mls10;
  WireFormat wire_format = mls_targeted_message;
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
  opaque authenticated_data<V>;
  uint32 sender_leaf_index;
  opaque kem_output<V>;
  opaque ciphertext_hash<V>;
} TargetedMessageTBS;

struct {
  opaque group_id<V>;
  uint64 epoch;
  opaque label<V> = "MLS 1.0 targeted message psk";
} PSKId;

struct {
  opaque application_data<V>;
  opaque padding[length_of_padding];
} TargetedMessageContent;
~~~

# Cryptographic Algorithms

All cryptographic operations on a targeted message use the cipher suite of
the MLS group in which the message is sent ({{Section 5.1 of !RFC9420}}). In
particular, the group's cipher suite determines:

- the KEM, KDF, and AEAD used for the HPKE encryption of the message content
  ({{application-data-encryption}}),
- the KDF underlying the `MLS-Exporter` and `ExpandWithLabel` derivations
  ({{authentication}} and {{sender-data-encryption}}), including the value
  `KDF.Nh`,
- the AEAD used to encrypt the sender authentication data
  ({{sender-data-encryption}}), including the values `AEAD.Nk` and `AEAD.Nn`,
- the hash function used to compute `ciphertext_hash`
  ({{authentication}}), and
- the signature algorithm used to sign and verify the `TargetedMessageTBS`
  struct ({{authentication}}).

# Authentication

A targeted message is authenticated by the sender's signature. The sender uses
the signature key of its `LeafNode`. The signature scheme is determined by the
cipher suite of the MLS group. The signature
is computed over the serialized `TargetedMessageTBS` struct and is included in
the `TargetedMessageSenderAuthData.signature` field:

~~~ tls
signature = SignWithLabel(sender_leaf_node_signature_private_key,
              "TargetedMessageTBS", targeted_message_tbs)
~~~

The `ciphertext_hash` field of `TargetedMessageTBS` is computed over the
`TargetedMessage.ciphertext` field with the hash function of the group's
cipher suite:

~~~ tls
ciphertext_hash = Hash(ciphertext)
~~~

Covering the ciphertext hash binds the signature to the encrypted message
content.

The recipient MUST verify the signature:

~~~ tls
VerifyWithLabel(sender_leaf_node.signature_key,
                "TargetedMessageTBS",
                targeted_message_tbs,
                signature)
~~~

In addition, targeted messages are authenticated using a pre-shared key (PSK),
exported through the MLS exporter for the epoch specified in the
`TargetedMessage`:

~~~ tls
targeted_message_psk =
  MLS-Exporter("targeted message", "psk", KDF.Nh)
~~~

The `targeted_message_psk` is used as the `psk` parameter in the Hybrid
Public Key Encryption (HPKE) encryption.
The corresponding `psk_id` parameter is the serialized `PSKId` struct.

## Additional Authenticated Data (AAD)

Targeted messages can include additional authenticated data (AAD) in the
`TargetedMessage.authenticated_data` field. This field is used to carry
application-specific data that is authenticated but not encrypted. The content
of this field is used as the `aad` parameter of the HPKE encryption
({{application-data-encryption}}).

# Encryption

Targeted messages use HPKE to encrypt the message content to a specific group
member.

Unlike the HPKE Base mode used in {{!RFC9420}}, targeted messages use HPKE PSK
mode ({{Section 5.1.2 of !RFC9180}}). The PSK is derived from the MLS group key
schedule, binding the encryption to the group state and providing authentication
that the sender holds the group's PSK.

## Padding

The `TargetedMessageContent.padding` field is set by the sender, by first
encoding the application data and then appending the chosen number of zero
bytes. A receiver identifies the `padding` field in a plaintext decoded from
`TargetedMessage.ciphertext` by first decoding the application data; then the
`padding` field comprises any remaining octets of plaintext. The `padding`
field MUST be filled with all zero bytes. A receiver MUST verify that there
are no non-zero bytes in the `padding` field, and if this check fails, the
enclosing `TargetedMessage` MUST be rejected as malformed. This check ensures
that the padding process is deterministic, so that, for example, padding
cannot be used as a covert channel.

## Application Data Encryption

The `TargetedMessageContent` struct is serialized and encrypted using HPKE.

The HPKE context is a `TargetedMessageContext` struct with the
following content:

~~~ tls
struct {
  uint32 recipient_leaf_index;
  uint32 sender_leaf_index;
} TargetedMessageContextData;

struct {
  opaque label<V> = "MLS 1.0 TargetedMessageData";
  TargetedMessageContextData context;
} TargetedMessageContext;
~~~

The `TargetedMessageContext` struct follows the same convention as
`EncryptContext` in {{Section 5.1.3 of !RFC9420}}, a label followed by
application context. Unlike `EncryptContext`, the `context` field is typed
rather than opaque, and the encryption uses PSK mode rather than Base mode.
The `context` field binds the encryption to the recipient and sender leaf
indices. The message is bound to the group state through the
`targeted_message_psk`, as described in {{group-state-binding}}.

The `TargetedMessageContext` struct is serialized as `hpke_context` and is used
by both the sender and the recipient. The recipient's leaf node HPKE encryption
key from the ratchet tree of the epoch specified in the `TargetedMessage` is
used as the recipient's public key `recipient_node_public_key` for the HPKE
encryption.

The content of the `TargetedMessage.authenticated_data` field is used as the
`aad` parameter for the HPKE encryption. The sender uses the single-shot
`SealPSK` API:

~~~ tls
(kem_output, ciphertext) = SealPSK(recipient_node_public_key,
                                   hpke_context,
                                   authenticated_data,
                                   targeted_message_content,
                                   targeted_message_psk,
                                   psk_id)
~~~

In full, the sender performs the following steps in order:

 - Derive the `targeted_message_psk` ({{authentication}}) and the
   `sender_auth_data_secret` ({{sender-data-encryption}}).
 - Compute `kem_output` and `ciphertext` by calling `SealPSK` with the
   serialized `TargetedMessageContent` as plaintext.
 - Compute `ciphertext_hash` from `ciphertext`, construct the
   `TargetedMessageTBS` struct, and compute the `signature` as described in
   {{authentication}}.
 - Assemble the `TargetedMessageSenderAuthData` struct from
   `sender_leaf_index`, `signature`, and `kem_output`, and encrypt it as
   described in {{sender-data-encryption}}, using a sample of the `ciphertext`
   computed above.

The `TargetedMessageSenderAuthData.kem_output` field is set to `kem_output`,
and the `TargetedMessage.ciphertext` field is set to `ciphertext`.

The recipient learns the `kem_output` and the `sender_leaf_index` by
decrypting `encrypted_sender_auth_data` before decrypting the content. The
`sender_leaf_index` is needed to construct the `TargetedMessageContextData`
struct:

~~~ tls
targeted_message_content = OpenPSK(kem_output,
                  recipient_node_private_key,
                  hpke_context,
                  authenticated_data,
                  ciphertext,
                  targeted_message_psk,
                  psk_id)
~~~

The functions `SealPSK` and `OpenPSK` are defined in {{Section 6.1 of
!RFC9180}}.

## Sender Data Encryption

`TargetedMessageSenderAuthData` is encrypted similarly to `MLSSenderData` as
described in {{Section 6.3.2 of !RFC9420}}. It contains the sender's leaf
index, the signature over `TargetedMessageTBS`, and the Key Encapsulation
Mechanism (KEM) output of the HPKE encryption.

The key and nonce provided to the Authenticated Encryption with Associated
Data (AEAD) are computed as the Key Derivation Function (KDF) of the first
KDF.Nh bytes of the `ciphertext` generated in {{application-data-encryption}}.
If the length of the ciphertext is less than KDF.Nh, the whole ciphertext is
used. As with the `targeted_message_psk`, the `sender_auth_data_secret` is
exported from the key schedule of the epoch specified in the
`TargetedMessage`. In pseudocode, the key and nonce are derived as:

~~~ tls
sender_auth_data_secret =
  MLS-Exporter("targeted message", "sender auth data secret", KDF.Nh)

ciphertext_sample = ciphertext[0..KDF.Nh-1]

sender_auth_data_key = ExpandWithLabel(sender_auth_data_secret,
                           "key", ciphertext_sample, AEAD.Nk)
sender_auth_data_nonce = ExpandWithLabel(sender_auth_data_secret,
                             "nonce", ciphertext_sample, AEAD.Nn)
~~~

The Additional Authenticated Data (AAD) for the `encrypted_sender_auth_data`
ciphertext is the first three fields of `TargetedMessage`:

~~~ tls
struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
} SenderAuthDataAAD;
~~~

# Recipient Validation

Upon receiving a `TargetedMessage`, the recipient MUST perform the following
steps in order:

 - Verify that `group_id` matches a group the recipient is a member of.
 - Verify that `epoch` corresponds to the current epoch of that group, or to a
   past epoch for which the recipient still has the necessary key material
   ({{messages-from-past-epochs}}).
 - Verify that `recipient_leaf_index` matches the recipient's own leaf index
   in the specified epoch.
 - Decrypt `encrypted_sender_auth_data` as described in
   {{sender-data-encryption}} and verify that `sender_leaf_index` refers to a
   non-blank leaf in the ratchet tree of the specified epoch.
 - Compute `ciphertext_hash` from `TargetedMessage.ciphertext` and verify the
   signature as described in {{authentication}}.
 - Decrypt `ciphertext` as described in {{application-data-encryption}}.
 - Verify that the `padding` field of the decrypted `TargetedMessageContent`
   contains only zero bytes, as described in {{padding}}.

The signature MUST be verified before `ciphertext` is decrypted. The
`TargetedMessageTBS` struct covers the `ciphertext` only through its hash,
which the recipient computes from the wire-format `ciphertext` field, so
signature verification does not depend on the decrypted content. Verifying
first ensures that no plaintext is produced from a message whose claimed
sender has not been authenticated. The decrypted `TargetedMessageContent`
MUST NOT be passed to the application before all of the above steps have
completed successfully.

If any of these steps fails, the `TargetedMessage` MUST be rejected.

## Messages from Past Epochs

Processing a `TargetedMessage` for a past epoch requires the recipient to
retain the following key material and state for that epoch:

- the exporter secret, or the `targeted_message_psk` and
  `sender_auth_data_secret` derived from it,
- the recipient's leaf node HPKE private key, and
- the leaf nodes of the ratchet tree, in order to look up the sender's leaf
  node.

Support for past epochs is OPTIONAL, accepting only the current epoch is the
most conservative behavior. Retaining key material from past epochs weakens
the Forward Secrecy properties described in {{forward-secrecy}}: targeted
messages for an epoch remain decryptable for as long as that epoch's key
material exists. Applications that accept messages from past epochs SHOULD
bound the number of retained epochs and SHOULD delete the corresponding key
material as soon as it is no longer needed.

# Security Considerations

This section describes the security properties of targeted messages and their
limitations relative to MLS application messages {{!RFC9420}}.

## Authentication

Targeted messages use two complementary authentication mechanisms. The sender's
signature ({{authentication}}) binds the message to the sender's identity:
the recipient verifies the signature against the sender's `LeafNode` signature
key, confirming that the holder of that key produced the message. The PSK
exported from the group key schedule provides a second layer that proves group
membership. Per {{Section 9.1 of !RFC9180}}, HPKE PSK mode provides outsider
authentication, ensuring that an entity that does not know the PSK cannot forge
a valid ciphertext. It does not, however, authenticate which PSK holder
produced the message. Sender identity relies entirely on the signature.

Because the PSK is derived from the MLS key schedule, it is only valid for a
specific group and epoch. The Forward Secrecy and Post-Compromise Security
guarantees of the group key schedule therefore extend to targeted messages. The
PSK also ensures that an attacker needs access to the private group state in
addition to the HPKE and signature private keys, improving confidentiality
guarantees against passive attackers and authentication guarantees against active
attackers.

## Group State Binding

Targeted messages are bound to the group state through the
`targeted_message_psk`. The key schedule of {{!RFC9420}} injects the
serialized `GroupContext` into the derivation of each epoch's secrets, so the
exporter-derived PSK commits to the full group state of the specified epoch,
including the tree hash and the confirmed transcript hash.

## Message Field Binding

The HPKE encryption is bound to the fields of a targeted message at one or
more layers. The `group_id` and `epoch` are bound through the `psk_id` and
through the epoch-derived PSK, both of which enter the HPKE key schedule. The
leaf indices of the recipient and the sender are bound through the HPKE `info`
input, which carries the `TargetedMessageContextData` struct. The
`authenticated_data` field is authenticated directly as the HPKE `aad`
parameter. The `kem_output` is bound through the HPKE key schedule, which
derives the encryption keys from the KEM shared secret. For the DHKEM variants
used by the cipher suites of {{!RFC9420}}, the shared-secret derivation also
includes the `kem_output` itself. Independently of these HPKE-layer bindings,
the sender's signature over the `TargetedMessageTBS` struct covers all of the
fields above together with the hash of the ciphertext.

## Signature Verification Before Processing

Because the PSK is shared among all group members and each member's HPKE
public key is available in the ratchet tree, any group member can construct
HPKE ciphertext that decrypts successfully while claiming a different sender
identity. The signature is the sole mechanism that binds the message to the
claimed sender.

The `TargetedMessageTBS` structure covers the `kem_output` and a hash of the
`ciphertext`, both of which are available before content decryption: the
former from the decrypted sender authentication data
({{sender-data-encryption}}), the latter from the wire format itself.
{{recipient-validation}} therefore requires the recipient to verify the
signature before decrypting the HPKE ciphertext, ensuring that plaintext is
never produced from a message whose claimed sender has not been
authenticated.

## Forward Secrecy

Targeted messages encrypt directly to the recipient's leaf node HPKE encryption
key. Unlike application messages in {{!RFC9420}}, which derive per-message keys
from a secret tree, targeted messages have no per-message key derivation.
Compromising the recipient's leaf private key therefore exposes all targeted
messages encrypted to that key within the epoch. Forward secrecy is at epoch
granularity only: it depends on the key schedule advancing to a new epoch and on
the recipient deleting the previous epoch's leaf private key. Applications that
require stronger forward secrecy guarantees SHOULD advance the epoch frequently.
Accepting targeted messages from past epochs requires retaining old key
material and further weakens forward secrecy, as described in
{{messages-from-past-epochs}}.

## Sender Identity Confidentiality

The `sender_auth_data_secret` used to encrypt the
`TargetedMessageSenderAuthData` is derived from the MLS exporter
({{sender-data-encryption}}) and is available to all group members. Sender
identity is therefore protected from the Delivery Service and from entities
outside the group, but not from other group members who obtain the encrypted
message.

The encryption mechanism is the same as the one used for `MLSSenderData` in
{{Section 6.3.2 of !RFC9420}}, and the analysis of {{Section 16.3 of
!RFC9420}} applies equally to targeted messages. In particular, using the
same `sender_auth_data_secret` with the same ciphertext sample more than once
would reuse an AEAD key and nonce pair; with the AEAD algorithms of the
cipher suites defined in {{!RFC9420}}, the probability of two ciphertext
samples colliding is no more than 2^-128.

## Replay Protection

Targeted messages do not include a generation counter or nonce at the protocol
level. A captured targeted message can therefore be replayed within the same
epoch and will pass all validation checks. However, targeted messages are a
stateless one-shot mechanism: replaying a message causes the recipient to see
duplicate content but does not change any group state. Applications that require
replay detection SHOULD include a unique nonce in the `authenticated_data`
field and track previously seen values.

# IANA Considerations

## MLS Wire Formats

The `mls_targeted_message` MLS Wire Format is used to send a message to a
single member of an MLS group.

 * Value: 0x0006 (suggested)
 * Name: mls_targeted_message
 * Recommended: Y
 * Reference: RFC XXXX

## MLS Signature Labels

### TargetedMessageTBS

* Label: "TargetedMessageTBS"
* Recommended: Y
* Reference: RFC XXXX

## MLS Public Key Encryption Labels

Although targeted messages use the HPKE PSK mode directly rather than
`EncryptWithLabel`, the label follows the same convention and is registered
to prevent collisions with other uses of the same HPKE keys.

### TargetedMessageData

* Label: "TargetedMessageData"
* Recommended: Y
* Reference: RFC XXXX

## MLS Exporter Labels

### targeted message

* Label: "targeted message"
* Recommended: Y
* Reference: RFC XXXX

--- back

# Test Vectors

The following test vectors exercise the receiver-side processing described in
{{recipient-validation}}. Because the HPKE encapsulation is randomized, the
sender-side operations are not reproducible from the inputs alone; sender
implementations can be tested by round-tripping against a receiver
implementation.

All vectors use the MTI MLS cipher suite
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. All values except `cipher_suite`,
`epoch`, the leaf indices, and `padding_length` (all decimal), `valid` (a
boolean), and `failure` (a name) are hex-encoded.

Each vector provides the group state held by the recipient:

- `group_id` and `epoch`: the group and epoch the message belongs to.
- `exporter_secret`: the exporter secret of that epoch, from which the
  `targeted_message_psk` and the `sender_auth_data_secret` are derived
  ({{authentication}} and {{sender-data-encryption}}).
- `sender_leaf_index` and `sender_leaf_node`: the sender's leaf index and
  serialized `LeafNode`, which provides the signature public key.
- `recipient_leaf_index` and `recipient_encryption_priv`: the recipient's
  leaf index and leaf node HPKE private key.

as well as the message and its expected plaintext:

- `targeted_message`: a serialized `MLSMessage` with the
  `mls_targeted_message` WireFormat, containing the `TargetedMessage`.
- `authenticated_data`: the expected content of the
  `TargetedMessage.authenticated_data` field.
- `application_data`: the expected application data after decryption.
- `padding_length`: the expected length of the zero-filled `padding` field of
  the decrypted `TargetedMessageContent`.
- `valid`: `true` if all steps of {{recipient-validation}} succeed, `false` if
  the message is to be rejected. A vector without this field is valid.
- `failure`: for a vector with `valid: false`, the first step of
  {{recipient-validation}} that fails, as one of:
  `decode` (the message does not parse), `group_id`, `epoch`,
  `recipient_leaf_index`, `sender_data` (decrypting or decoding
  `encrypted_sender_auth_data`), `sender_leaf_index`, `signature`,
  `ciphertext` (decrypting `ciphertext`), or `padding`.

For a vector with `valid: false`, `application_data` is empty and
`padding_length` is 0.

The ratchet tree of the epoch has exactly two non-blank leaves, at
`sender_leaf_index` and `recipient_leaf_index`. The recipient retains no
key material for past epochs.

A verifier performs the steps of {{recipient-validation}} on
`targeted_message`. For a valid vector, it checks that all validation steps
succeed, that the decrypted application data matches `application_data`, and
that the padding has length `padding_length`. For an invalid vector, it checks
that the message is rejected at the step named by `failure`.

## Vector 1

~~~
cipher_suite: 1
epoch: 1
sender_leaf_index: 0
recipient_leaf_index: 1
padding_length: 0
group_id: f2262a40482cec0303230db5ac5fcf31
exporter_secret:
  e7d6fb6557f6b0dd7b8b8a1eeb0ed16b3737b7564377aa4aa831999dd1bfbf6a
sender_leaf_node:
  205d4f25388282dbeed3dc7a83c297be2d1cfb0120aeec7b776eaf1ce5c67b8d
  2220dd42b86b0339901510cb2a16018fa89c5315e738a6e15d09b5c0c373a1b9
  179400010673656e64657202000106000100020003000002000101000000006a
  8560a3000000006af42cb3004040cabc6b771ebb2331ee6a63497c8949fd6335
  3fd42657596c7b1ee0e1a50e45bde622d871ac9e6b07060f02d65f162575a542
  a81cf07b019397d46b84d1a6c806
recipient_encryption_priv:
  28e4c3614487885ffcb6f3f9a59a3a2a9109650890e10ffae0dc2e00df625ab8
authenticated_data:
application_data:
  4b41542074657374207061796c6f616420666f72207461726765746564206d65
  737361676573
targeted_message:
  0001000610f2262a40482cec0303230db5ac5fcf310000000000000001000000
  010040777ffcb757af2885bd1d07bb2b181592847fb3735e8da278352c07a557
  a08d7ca230f2bd254579b4e91c396fdd15e4c9196b345f6162787581858f6f9f
  60ae4e8299a00d3fbc4018279f6630a3bdf2c3ff70a15596820404c0b8098131
  795b6d247f71afc96562fd652e4bd28ca153d093f9c1c134d1857e37f852e72b
  d9eb8a03ba6eb23c60484f12612ae7a7194a0430d6ee563e0e0a111bb9e46eee
  74b8f5f2f2017c7c1f6ee1120334776b42a368
~~~

## Vector 2

~~~
cipher_suite: 1
epoch: 5
sender_leaf_index: 0
recipient_leaf_index: 2
padding_length: 64
group_id: 494bb867937321cfa1ed12e38beb4ebc
exporter_secret:
  099416d0ebdcfc56c4b902371abe0e56453818791e851a1d99d8cd2e3d9fa5d8
sender_leaf_node:
  2069ed695cce5e378511ec918ecfcf0ec77aef8419b8aefff56fc69ae1bde4fe
  1220d5949ec3e201eb1131cca57e20552bf355300fb311274b2cf7fd568f2e11
  2f0800010673656e64657202000106000100020003000002000101000000006a
  8560a3000000006af42cb300404028bad1f073bd390cac5c8d0143baf45c5f47
  623694d96c87f25eef82d4f8aff759075d6bd7c21b41bdd0dede88352da82ad5
  0144a122895422207d41059ec60d
recipient_encryption_priv:
  aa30b0aedaa86b1197cc8f8d4dc0e0427ca3b3b31e33361a7d9e4ed43a632bd0
authenticated_data: 726571756573742d69643d3432
application_data: 7365636f6e64207461726765746564207061796c6f6164
targeted_message:
  0001000610494bb867937321cfa1ed12e38beb4ebc0000000000000005000000
  020d726571756573742d69643d343240770d3fc8dad6abb190188ea5e3a35bbc
  949520be96cb6fc4619b83165fc50500d9f04b6ff70717d9df81aeb3b7f99c04
  2470cdee8adbc75419552c20802b968b75a3cc577ea5dc9ff4cd8d0cfccf9be1
  f963b6ae360d643aa0e82b5e373e0696d01b77409543a8cc820871e6fb77a224
  8c0ab36c74e5f9994068e5cd351ad109febddbc9dabff823763b59647f2f20d9
  7307c1b52d784186c4349ae12fbece479657c5080146b323a7e3ddd82dd812ac
  8af669577a59fd6409dfc537c5ce7723d006ca30aa642ffa2709187d1d4616e8
  13628c67aed7575de8b6014615afa038dc4c
~~~

## Vector 3

~~~
cipher_suite: 1
epoch: 42
sender_leaf_index: 3
recipient_leaf_index: 7
padding_length: 128
group_id: e87d0d3f4c6704f4c7b293803608a2ca
exporter_secret:
  2966045954d98555c3eb113c09053631d0a5da1331409fc2183f6e07ebb73a66
sender_leaf_node:
  207ced1c787759a5538d0b4b40231a5c35417593458ac8f79f4270a20f4f5be7
  2120ba40b1f4ed2a356eda58ed61fc9933324d2a2a2c9669257b2918f9bad57c
  5e7700010673656e64657202000106000100020003000002000101000000006a
  8560a3000000006af42cb3004040fa4214542d9a917fc3520a47692dd4c9ce4f
  a9f1786b0414b1209f46e0f1df687c0da0c558628918794beb0b2fd9a4ad2d08
  47722c552742e1a4ac0464e81b00
recipient_encryption_priv:
  24c98ea1980e34892cfe90cb87c4e6757fcdcde7cd28e3b51d100ea907bdae2b
authenticated_data:
application_data:
targeted_message:
  0001000610e87d0d3f4c6704f4c7b293803608a2ca000000000000002a000000
  0700407775080b98cd1a824901a329abf71dbb638ea997cfe0971100c878080a
  214937c645c42a187f2eece6e2728c14be16f1e86b7053940cdc0e483e32dd78
  42bb3bc51bc492556c55088f5087bf5a0f31d264ba94dd08c3b876384b6afd41
  e2d1424b0c2eef2eb61f923fd612f85583c8f5a831313f8f8e7021409157ccd8
  6dba88622b7ff3c984bbf93ced6898e990414032b5cb610af88ac92e21ec00a2
  69a3cf0a3073075a000952bac39e41074361012ad37a8194b0b9b42382b1e3e7
  191560bc664a8678555eb2d53389d1f0b7c231b3b4b4f1dc68f59e627e806ccd
  b000c98f3074e120b03a91746f77185af95b6446813a95132ef5c153587a7856
  52a77cd85ef344d1134db24fbe38
~~~

## Vector 4

Vector 4 has empty `application_data` and no padding, so its `ciphertext` is 17
bytes, shorter than KDF.Nh, and the whole `ciphertext` is the sample used in
{{sender-data-encryption}}.

~~~
valid: true
cipher_suite: 1
epoch: 0
sender_leaf_index: 0
recipient_leaf_index: 1
padding_length: 0
group_id: 903e64ae19f9e8705b1197e172e6c565
exporter_secret:
  fb55c088454fd038ffcea59e5230a3e7db2173bcf39abe19b445952d656039eb
sender_leaf_node:
  207ce5c3e161e456926e6708e9f36bd0b9fdbf1046b3ddffbd391b0d744d6e16
  3f20da923f2a67d26cec64ee34f1e4af7eb2c67699345b5c1e67fdd37c2ba76f
  0aa700010673656e646572020001020001000002000101000000006ae8b00900
  0000006b577c190040407f4b358f2f6034052b5279ec15e26b355f28047a67d3
  b5f0ffc3f251efa2b90f106751b5316a244869f0c712bc8ceb1f67020ac86738
  cbd1ca66566149ab8100
recipient_encryption_priv:
  3c26fe01f4ea565b4403337852ba6dfa885baafd2932b022cb09542f23622250
authenticated_data:
application_data:
targeted_message:
  0001000610903e64ae19f9e8705b1197e172e6c5650000000000000000000000
  01004077e46df1fab402176140976b189a116f8e87153db87c6b7bfd8614c5a8
  24f5cf5ab01c555d3a033d286510c4c0b9bd65f0a8da09fe2d7e3b268dff2059
  042f079c1e625c2f799a489fb181e5e8763061deee008684b3c9b563d36f4ad4
  cd34a0077ec1c607a9c29634df3d84b42325d123e01202e51b632211bf124cca
  9a31349be301dd8210bfa80614
~~~

## Vector 5

Vector 5 has a `ciphertext` of exactly KDF.Nh bytes.

~~~
valid: true
cipher_suite: 1
epoch: 1
sender_leaf_index: 1
recipient_leaf_index: 0
padding_length: 0
group_id: 53611d3a730ec0f49f3871118201d235
exporter_secret:
  e0463c9e6c69375d3389a5a9a78db3cd0c8a54fca49d609e80f76cb0ca6a9917
sender_leaf_node:
  20a818c8268a485e498733aaef9196c4305960d214c57e3348aa0aceced474bd
  5d20386f23018c223480b071ea61608420a96b404c79af28e9d1992c0425e72b
  156f00010673656e646572020001020001000002000101000000006ae8b00900
  0000006b577c1900404058a2a8d23886444d40bbde549e49e699e7a38859b581
  5a1519225443618d46f37cac0e0915d358321fe9c0599112114362f96ac377ea
  953151b8c467c0ccda0d
recipient_encryption_priv:
  a7b776c804ec3fe07541f8b1a5a2a493426b2d957321e1b04cd58af3eac0ec35
authenticated_data:
application_data: 000102030405060708090a0b0c0d0e
targeted_message:
  000100061053611d3a730ec0f49f3871118201d2350000000000000001000000
  00004077088895e685dbe1070524c7fd672a18566c82f7f69b13f23eaaea7290
  5a1f9604465b58533af7ce59649edb782108d2644cf798b18cdfdb0e024740ae
  856b1716b4f502f334c9cc6101c08fb89b18de564b0f725b1fcf93c4292b78a7
  c9a756bd9cb468df2d662d4d4f05ebaeae86447aeba8fb40a8ae582080cb7b99
  c8a2a9183d4d4b1a9103356d78d881d98aa6fcfaefa0403a661932d5
~~~

## Vector 6

In Vector 6, `encrypted_sender_auth_data` decrypts correctly but names leaf 4,
which is blank.

~~~
valid: false
failure: sender_leaf_index
cipher_suite: 1
epoch: 7
sender_leaf_index: 3
recipient_leaf_index: 5
padding_length: 0
group_id: 291bc66f1449ccdbf114dd695ceb48c0
exporter_secret:
  74b2c549ad4de07d41acb30dbf779913155374c9b64370c6f688fcf500517316
sender_leaf_node:
  207f45ac839d75b23032e2d3b351d1bd181eebdd2e02b9bf12aec7731b371b51
  6c200a82529548fdf638390767ad6eeca9b38aed9dbe688f80055e92ab653a60
  192f00010673656e646572020001020001000002000101000000006ae8b00900
  0000006b577c19004040293864f86d2e6c78dc2c220a8c8b20046978ff3d74df
  dc609a5b23a6382a836a26533db6549455d456c32ed8538a3237275c2924c96a
  051184c61e74e724760e
recipient_encryption_priv:
  f15cf5e9ff7d6d85f5d1668b3a13249b469f722051838113d9dc0d553a2d3b06
authenticated_data: 726571756573742d69643d3432
application_data:
targeted_message:
  0001000610291bc66f1449ccdbf114dd695ceb48c00000000000000007000000
  050d726571756573742d69643d3432407730e9c0df401667c587bac3e7793e87
  7de747553ec8ca7624668452778e315c739554c424e4e6f2d97382d1fc2389c2
  fd2fdcb8ff9b2786ff3c82ce0eead58242019bc080312f7d2b083c69b9e5e56e
  8bcf26f549fee63fd2597dba23a34405177b5aee055f980c010c4b2ac0ae7e24
  366ab9196a745c2b3959fabc18d987d30e20fa3f457520ec76cf7ed711b5b2ee
  3e39e711744d3e49d0a7939b14647bb2981818d925601c9c76c79fe29befe749
  a565
~~~

## Vector 7

Vector 7 is correctly signed and decrypts, but the third of its four padding
bytes is 0x01.

~~~
valid: false
failure: padding
cipher_suite: 1
epoch: 7
sender_leaf_index: 3
recipient_leaf_index: 5
padding_length: 0
group_id: 5a3630b342a025782103b19ad7f10e00
exporter_secret:
  ccfbdd96a069073057844adfeca9f154e901fcef9e57e35a30aa01f51e2c3826
sender_leaf_node:
  20978e8b48b57ba176ea3104db0729fc53b3514636dd47a12e4108a0e02a6161
  462025bf6ce0ca23a76faa75c6851622e9b07c07a548d1da8d3b5cbff2fe4b54
  80ce00010673656e646572020001020001000002000101000000006ae8b00900
  0000006b577c190040402116c459ee95961a3809d1d1e63f5db4def0bee3adb4
  8a058080f1d858ff85f642ae66ba6133588404d2127c423cd0e2009212d03804
  1d66a19ab748f83a6f03
recipient_encryption_priv:
  3fe8a69e253749253417d7a8c107e97a71904c57e95c05da0248d573cdd69357
authenticated_data: 726571756573742d69643d3432
application_data:
targeted_message:
  00010006105a3630b342a025782103b19ad7f10e000000000000000007000000
  050d726571756573742d69643d34324077828ea9b0625cae93e59eb5255ec1a1
  39f3d3fc454849d6a8702cf9160b777a0b8f35ba19cbe8aa9fe9a87486f77b73
  09ca0c9c356496094db0e8de899fccb66747499ed727a27d04baa36122f8308a
  1520fffe7a0bb082e85d9cb76bac9ee3cbab4963060338a54e29a97ccaba3b1f
  80bc8ecbfa0fe0563d63820d6f6a920014c736227475c7155eeb07df791ada0d
  3777681c36b06b36e4c146898b81296a498022ccecafc5a33c5b75b61fb7ae09
  d2fb1b77c917
~~~

# Change Log
{:removeInRFC="true"}

draft-ietf-mls-targeted-messages-02:

- Replaced the `TargetedMessageTBM` struct with the
  `TargetedMessageContextData` struct, which carries the leaf indices and is
  used as the `context` field of the HPKE info.
- Used the content of the `authenticated_data` field directly as the HPKE
  `aad` parameter.
- Replaced the two-step `SetupPSKS` and `Context.Seal` flow with the
  single-shot `SealPSK` API, which is possible now that the AAD no longer
  depends on the `kem_output`.
- Added a security consideration describing how each message field is bound.
- Updated the test vectors.
- Added `valid` and `failure` fields to the test vector format, and test
  vectors for a ciphertext shorter than KDF.Nh, a ciphertext of exactly
  KDF.Nh bytes, a blank sender leaf, and non-zero padding.

draft-ietf-mls-targeted-messages-01:

- Changed the intended status from Informational to Standards Track.
- Added a `ciphertext_hash` field to `TargetedMessageTBS` so that the
  signature covers the message content; `TargetedMessageTBM` now carries
  `sender_leaf_index` and `kem_output` directly.
- Replaced the single-shot `SealPSK` call with `SetupPSKS` followed by
  `Context.Seal`, and specified the full sender-side order of operations.
- Specified the recipient-side processing steps, including signature
  verification before content decryption.
- Emptied the `context` field of `TargetedMessageContext`; the group state
  binding is provided by the PSK, as described in the new Group State
  Binding security consideration.
- Added a Cryptographic Algorithms section binding all operations to the
  group's cipher suite.
- Bound the recipient's public key and the exported secrets to the epoch
  specified in the message, and added a Messages from Past Epochs section.
- Referenced the analysis of sender data encryption from RFC 9420 in the
  security considerations.
- Registered the "TargetedMessageData" MLS Public Key Encryption Label.
- Added a Test Vectors appendix.
- Editorial fixes: corrected the RFC 9180 section reference for PSK mode and
  aligned the IANA wire format description with the single-recipient design.

# Acknowledgments
{:numbered="false"}
