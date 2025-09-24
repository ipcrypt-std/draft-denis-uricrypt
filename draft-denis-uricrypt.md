---
title: "Prefix-Preserving Encryption for URIs"
abbrev: URICrypt
docname: draft-denis-uricrypt-latest
category: info
ipr: trust200902
submissionType: independent
keyword: Internet-Draft
author:
  - name: "Frank Denis"
    organization: "Fastly Inc."
    email: fde@00f.net
date: "2025"
v: 3
stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

--- abstract

This document specifies URICrypt, a deterministic, prefix-preserving
encryption scheme for Uniform Resource Identifiers (URIs). URICrypt
encrypts URI paths while preserving their hierarchical structure,
enabling systems that rely on URI prefix relationships to continue
functioning with encrypted URIs. The scheme provides authenticated
encryption for each URI path component, preventing tampering,
reordering, or mixing of encrypted segments.

--- middle

# Introduction

This document specifies URICrypt, a method for encrypting Uniform
Resource Identifiers (URIs) while preserving their hierarchical
structure. The primary motivation is to enable systems that rely on
URI prefix relationships for routing, filtering, or access control to
continue functioning with encrypted URIs.

URICrypt achieves prefix preservation through a chained encryption
model where the encryption of each URI component depends
cryptographically on all preceding components. This ensures that URIs
sharing common prefixes produce ciphertexts that also share common
encrypted prefixes.

The scheme uses an extendable-output function (XOF) as its cryptographic primitive
and provides authenticated encryption for each component, preventing
tampering, reordering, or mixing of encrypted segments.

## Use Cases and Motivations

The main motivations include:

* Access Control in CDNs: Content Delivery Networks often use URI
  prefixes for routing and access control. URICrypt allows encrypting
  resource paths while preserving the prefix structure needed for
  CDN operations.

* Privacy-Preserving Logging: Systems can log encrypted URIs
  without exposing sensitive path information, while still enabling
  analysis based on URI structure.

* Confidential Data Sharing: When sharing links to sensitive
  resources, URICrypt prevents the path structure itself from
  revealing confidential information.

* Token-Based Access Systems: Systems that issue time-limited
  access tokens can use URICrypt to obfuscate the underlying
  resource location while maintaining routability.

* Multi-Tenant Systems: In systems where multiple tenants share
  infrastructure, URICrypt can isolate tenant data while allowing
  shared components to be processed efficiently.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP
14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as
shown here.

Throughout this document, the following terms and conventions apply:

* URI: Uniform Resource Identifier as defined in {{!RFC3986}}.

* URI Component: A segment of a URI path, typically separated by
  '/' characters. For encryption purposes, components include the
  trailing separator except for the final component.

* Scheme: The URI scheme (e.g., "https://") which is preserved in
  plaintext.

* XOF: Extendable-Output Function, a hash function that can
  produce output of arbitrary length.

* SIV: Synthetic Initialization Vector, a 16-byte value derived
  from the accumulated state of all previous components, used for
  authentication and as input to keystream generation.

* Domain Separation: The practice of using distinct inputs to
  cryptographic functions to ensure outputs for different purposes
  are not compatible.

* Prefix-Preserving Encryption: An encryption scheme where if two
  plaintexts share a common prefix, their corresponding ciphertexts
  also share a common (encrypted) prefix.

* Chained Encryption: A mode where encryption of each component
  depends cryptographically on all preceding components.

# URI Processing

This section describes how URIs are processed for encryption and
decryption.

## URI Component Extraction

Before encryption, a URI must be split into its scheme and path
components. The path is further divided into individual components for
chained encryption.

### Full URIs

For a full URI including a scheme:

~~~
Input:  "https://example.com/a/b/c"

Components:

- Scheme: "https://"
- Component 1: "example.com/"
- Component 2: "a/"
- Component 3: "b/"
- Component 4: "c"
~~~

Note that all components except the last include the trailing '/'
character. This ensures proper reconstruction during decryption.

### Path-Only URIs

For URIs without a scheme:

~~~
Input:  "/a/b/c"

Components:

- Scheme: "" (empty)
- Component 1: "a/"
- Component 2: "b/"
- Component 3: "c"
~~~

The leading '/' is not treated as a separate component but is
implied during reconstruction.

## Component Reconstruction

During decryption, components are joined to reconstruct the original
path:

~~~
Components: ["example.com/", "a/", "b/", "c"]
Reconstructed Path: "example.com/a/b/c"

When combined with the scheme: "https://example.com/a/b/c"
~~~

# Cryptographic Operations

URICrypt uses three parallel TurboSHAKE128 {{!I-D.draft-irtf-cfrg-kangarootwelve}} instances for different
purposes, all initialized from the same base hasher.

## Hasher Initialization {#hasher-init}

The base hasher is initialized with the secret key and context
parameter using length-prefixed encoding to prevent ambiguities.

Two hashers are derived from the base hasher:

1.  Components Hasher: Updated with each component's plaintext to
    generate SIVs

2.  Base Keystream Hasher: Used as the starting point for generating
    keystream for each component

The initialization process:

~~~
base_hasher = TurboSHAKE128()
base_hasher.update(len(secret_key))
base_hasher.update(secret_key)
base_hasher.update(len(context))
base_hasher.update(context)

components_hasher = base_hasher.clone()
components_hasher.update("IV")

base_keystream_hasher = base_hasher.clone()
base_keystream_hasher.update("KS")
~~~

## Component Encryption

For each component, the encryption process is:

1.  Update `components_hasher` with the component plaintext
2.  Generate SIV from `components_hasher` (16 bytes)
3.  Create `keystream_hasher` by cloning `base_keystream_hashe`r and updating with SIV
4.  Calculate padding needed for base64 encoding
5.  Generate keystream of length `(component_length + padding)`
6.  XOR padded component with keystream
7.  Output SIV concatenated with `encrypted_component`

The padding length is calculated as:
`padding_len = (3 - (16 + component_len) % 3) % 3`

## Component Decryption

For each encrypted component, the decryption process is:

1.  Read SIV from input (16 bytes)
2.  Create `keystream_hasher` by cloning `base_keystream_hasher` and updating with SIV
3.  Read encrypted component data (length determined from encoding)
4.  Generate keystream and decrypt component
5.  Remove padding to recover plaintext
6.  Update `components_hasher` with plaintext
7.  Generate expected SIV from `components_hasher`
8.  Compare expected SIV with received SIV (constant-time)
9.  If mismatch, return `error`

Any teampering with the encrypted data will cause the SIV comparison to fail.

## Padding and Encoding

Each encrypted component `(SIV || ciphertext)` is padded to make its
length a multiple of 3 bytes, enabling clean base64 encoding without
padding characters.

The final output is encoded using URL-safe base64 {{!RFC4648}} without padding.

# Algorithm Specification

This section provides the complete algorithms for encryption and
decryption.

## Encryption Algorithm

Input: secret_key, context, uri_string

Output: encrypted_uri

Steps:

1.  Split URI into scheme and components
2.  Initialize hashers as described in {{hasher-init}}
3.  `encrypted_output = empty byte array`
4.  For each component:
      - `Update components_hasher with component`
      - `SIV = components_hasher.read(16)`
      - `keystream_hasher = base_keystream_hasher.clone()`
      - `keystream_hasher.update(SIV)`
      - `padding_len = (3 - (16 + len(component)) % 3) % 3`
      - `keystream = keystream_hasher.read(len(component) + padding_len)`
      - `padded_component = component concatenated with zeros(padding_len)`
      - `encrypted_part = padded_component XOR keystream`
      - `encrypted_output = encrypted_output concatenated with SIV concatenated with encrypted_part`

5.  `base64_output = base64url_encode(encrypted_output)`
6.  Return `scheme + base64_output`

## Decryption Algorithm

Input: secret_key, context, encrypted_uri

Output: decrypted_uri or error

Steps:

1.  Split encrypted URI into scheme and base64 part
2.  `decoded = base64url_decode(base64_part)`. If `decode fails`, return `error`
3.  Initialize hashers as described in {{hasher-init}}
4.  `decrypted_components = empty list`
5.  `input_stream = Stream(decoded)`
6.  While input_stream not empty:
      - `SIV = input_stream.read(16)`. If not enough bytes, return `error`
      - `keystream_hasher = base_keystream_hasher.clone()`
      - `keystream_hasher.update(SIV)`
      - Determine component length from remaining data and padding
      - `encrypted_part = input_stream.read(component_length)`
      - `keystream = keystream_hasher.read(len(encrypted_part))`
      - `padded_plaintext = encrypted_part XOR keystream`
      - `component = remove_padding(padded_plaintext)`
      - Update `components_hasher` with component
      - `expected_SIV = components_hasher.read(16)`
      - If `constant_time_compare(SIV, expected_SIV) == false`: return `error`
      - `decrypted_components.append(component)`

7.  `decrypted_path = join(decrypted_components)`
8.  Return `scheme + decrypted_path`

# Implementation Details

## TurboSHAKE128 Usage

Implementations MUST use TurboSHAKE128 with a domain separation
parameter of `0x1F` for all operations. The TurboSHAKE128 XOF is used
for:

* Generating SIVs from the components hasher
* Generating keystream for encryption/decryption
* All hash operations in the initialization

TurboSHAKE128 is specified in {{FIPS202}} and provides the security
properties needed for this construction.

## Key and Context Handling

The secret_key MUST be at least 16 bytes long. Keys shorter than 16
bytes MUST be rejected. Implementations SHOULD validate that the key
does not consist of repeated patterns (e.g., identical first and
second halves) as a best practice.

The context parameter is a string that provides domain separation.
Different applications SHOULD use different context strings to prevent
cross-application attacks. The context string MAY be empty.

Both key and context are length-prefixed when absorbed into the base
hasher:

~~~
base_hasher.update(len(secret_key) as uint8)
base_hasher.update(secret_key)
base_hasher.update(len(context) as uint8)
base_hasher.update(context)
~~~

The length is encoded as a single byte, limiting keys and contexts to
255 bytes. This is sufficient for all practical use cases.

## Error Handling

Implementations MUST NOT reveal the cause of decryption failures. All
error conditions (invalid base64, incorrect padding, SIV mismatch,
insufficient data) MUST result in identical, generic error messages.

SIV comparison MUST be performed in constant-time to prevent timing
attacks.

# Security Considerations

URICrypt provides confidentiality and integrity for URI paths while
preserving prefix relationships. The security properties depend on:

* Key Secrecy: The security of URICrypt depends entirely on the
  secrecy of the secret key. Keys MUST be generated using a
  cryptographically secure random number generator {{!RFC4086}} and
  stored securely.

* Deterministic Encryption: URICrypt is deterministic - identical
  inputs produce identical outputs. This allows observers to detect
  when the same URI is encrypted multiple times. Applications
  requiring unlinkability SHOULD incorporate additional entropy (e.g.,
  via the context parameter).

* Prefix Preservation: While essential for functionality, prefix
  preservation leaks information about URI structure. Systems where
  this information is sensitive SHOULD consider alternative
  approaches.

* Context Separation: The context parameter prevents cross-context
  attacks. Applications MUST use distinct contexts for different
  purposes, even when sharing keys.

* Component Authentication: Each component is authenticated via
  the SIV mechanism. Any modification, reordering, or truncation of
  components will be detected during decryption.

* Length Leakage: The length of each component is preserved in the
  encrypted output. Applications sensitive to length information
  SHOULD consider padding components to fixed lengths.

* Key Reuse: Using the same key with different contexts is safe, but
  using the same (key, context) pair for different applications is
  NOT RECOMMENDED.

# IANA Considerations

This document has no actions for IANA.


# Pseudocode

## URI Component Extraction

~~~
function extract_components(uri_string):
  if uri_string contains "://":
     scheme = substring before "://"
     path = substring after "://"
  else:
     scheme = ""
     path = uri_string

  if path starts with "/":
     path = substring after first "/"

  components = []
  while path not empty:
     slash_pos = find("/", path)
     if slash_pos found:
        component = substring(0, slash_pos + 1)
        path = substring(slash_pos + 1)
        components.append(component)
     else:
        components.append(path)
        path = ""

  return (scheme, components)
~~~

## Hasher Initialization

~~~
function initialize_hashers(secret_key, context):
  // Validate key length
  if len(secret_key) < 16:
     return error("Key too short")

  // Validate key pattern (best practice)
  if len(secret_key) >= 32:
     first_half = secret_key[0:len(secret_key)/2]
     second_half = secret_key[len(secret_key)/2:]
     if first_half == second_half:
        return error("Weak key pattern detected")

  // Initialize base hasher
  base_hasher = TurboSHAKE128(0x1F)

  // Absorb key and context with length prefixes
  base_hasher.update(uint8(len(secret_key)))
  base_hasher.update(secret_key)
  base_hasher.update(uint8(len(context)))
  base_hasher.update(context)

  // Create components hasher
  components_hasher = base_hasher.clone()
  components_hasher.update("IV")

  // Create base keystream hasher
  base_keystream_hasher = base_hasher.clone()
  base_keystream_hasher.update("KS")

  return (components_hasher, base_keystream_hasher)
~~~

## Encryption Algorithm

~~~
function uricrypt_encrypt(secret_key, context, uri_string):
  // Extract components
  (scheme, components) = extract_components(uri_string)

  // Initialize hashers
  (components_hasher, base_keystream_hasher) =
      initialize_hashers(secret_key, context)
  if error: return error

  encrypted_output = bytearray()

  // Process each component
  for component in components:
     // Update components hasher
     components_hasher.update(component)

     // Generate SIV
     siv = components_hasher.squeeze(16)

     // Create keystream hasher for this component
     keystream_hasher = base_keystream_hasher.clone()
     keystream_hasher.update(siv)

     // Calculate padding
     component_len = len(component)
     padding_len = (3 - (16 + component_len) % 3) % 3

     // Generate keystream
     keystream = keystream_hasher.squeeze(component_len + padding_len)

     // Pad component
     padded_component = component + bytearray(padding_len)

     // Encrypt
     encrypted_part = xor_bytes(padded_component, keystream)

     // Append to output
     encrypted_output.extend(siv)
     encrypted_output.extend(encrypted_part)

  // Base64 encode
  base64_output = base64_urlsafe_no_pad_encode(encrypted_output)

  // Return with scheme
  return scheme + base64_output
~~~

## Decryption Algorithm

~~~
function uricrypt_decrypt(secret_key, context, encrypted_uri):
  // Split scheme and base64
  if encrypted_uri contains "://":
     scheme = substring before "://"
     base64_part = substring after "://"
  else:
     scheme = ""
     base64_part = encrypted_uri

  // Decode base64
  try:
     decoded = base64_urlsafe_no_pad_decode(base64_part)
  catch:
     return error("Decryption failed")

  // Initialize hashers
  (components_hasher, base_keystream_hasher) =
      initialize_hashers(secret_key, context)
  if error: return error

  decrypted_components = []
  input_stream = ByteStream(decoded)

  // Process each component
  while not input_stream.empty():
     // Read SIV
     siv = input_stream.read(16)
     if len(siv) != 16:
        return error("Decryption failed")

     // Create keystream hasher
     keystream_hasher = base_keystream_hasher.clone()
     keystream_hasher.update(siv)

     // Determine component length
     remaining = input_stream.remaining()
     if remaining == 0:
        return error("Decryption failed")

     // Find valid component length by checking padding
     component_data = None
     for possible_len in range(1, remaining + 1):
        total_len = 16 + possible_len
        padding_len = (3 - total_len % 3) % 3
        if possible_len >= padding_len:
           component_data = input_stream.peek(possible_len)
           break

     if component_data is None:
        return error("Decryption failed")

     // Read encrypted data
     encrypted_part = input_stream.read(len(component_data))

     // Generate keystream and decrypt
     keystream = keystream_hasher.squeeze(len(encrypted_part))
     padded_plaintext = xor_bytes(encrypted_part, keystream)

     // Remove padding
     padding_len = (3 - (16 + len(encrypted_part)) % 3) % 3
     component = padded_plaintext[:-padding_len] if padding_len > 0 else padded_plaintext

     // Update hasher with plaintext
     components_hasher.update(component)

     // Generate expected SIV
     expected_siv = components_hasher.squeeze(16)

     // Authenticate (constant-time comparison)
     if not constant_time_equal(siv, expected_siv):
        return error("Decryption failed")

     decrypted_components.append(component)

  // Reconstruct URI
  if scheme and decrypted_components:
     path = "".join(decrypted_components)
     return scheme + path
  elif decrypted_components:
     return "/" + "".join(decrypted_components)
  else:
     return ""
~~~

## Padding and Encoding

~~~
function calculate_padding(component_len):
  return (3 - (16 + component_len) % 3) % 3

function base64_urlsafe_no_pad_encode(data):
  // Use standard base64 encoding
  encoded = standard_base64_encode(data)
  // Make URL-safe and remove padding
  encoded = encoded.replace('+', '-')
                 .replace('/', '_')
                 .rstrip('=')
  return encoded

function base64_urlsafe_no_pad_decode(encoded):
  // Add padding if needed
  padding = (4 - len(encoded) % 4) % 4
  if padding > 0:
     encoded = encoded + ('=' * padding)
  // Make standard base64
  encoded = encoded.replace('-', '+')
                 .replace('_', '/')
  // Decode
  return standard_base64_decode(encoded)
~~~

# Test Vectors

## Test Vector 1: Full URI

~~~
Input:
secret_key: 0x0102030405060708090a0b0c0d0e0f10
context: "test-context"
uri: "https://example.com/a/b/c"

Expected Output:
"https://AbCdEfGhIjKlMnOpQrStUvWxYz"

(Actual test vectors will be generated from a reference
implementation)
~~~

## Test Vector 2: Path-Only URI

~~~
Input:
secret_key: 0x0102030405060708090a0b0c0d0e0f10
context: "test-context"
uri: "/a/b/c"

Expected Output:
"/AbCdEfGhIjKlMnOpQrStUvWxYz"
~~~

## Test Vector 3: Multi-Component Path

~~~
Input:
secret_key: 0x0102030405060708090a0b0c0d0e0f10
context: "test-context"
uri: "https://cdn.example.com/videos/2025/03/file.mp4"

Expected Output:
"https://AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
~~~
