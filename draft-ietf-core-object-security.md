---
title: Object Security of CoAP (OSCOAP)
docname: draft-ietf-core-object-security-latest

ipr: trust200902
wg: CoRE Working Group
cat: std

coding: utf-8
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        email: francesca.palombini@ericsson.com
      -
        ins: L. Seitz
        name: Ludwig Seitz
        org: SICS Swedish ICT
        email: ludwig@sics.se

normative:

  RFC2119:
  RFC5988:
  RFC6347:
  RFC7049:
  RFC7252:
  RFC7641:
  RFC7959:
  RFC8152:
  I-D.amsuess-core-repeat-request-tag:
  
informative:

  RFC3986:
  RFC5869:
  RFC7228:
  RFC7515:
  RFC8075:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-coap-tcp-tls:
  I-D.bormann-6lo-coap-802-15-ie:
  I-D.greevenbosch-appsawg-cbor-cddl:
  I-D.hartke-core-e2e-security-reqs:
  I-D.mattsson-core-coap-actuators:
  I-D.seitz-ace-oscoap-profile:
  I-D.tiloca-core-multicast-oscoap:

--- abstract

This document defines Object Security of CoAP (OSCOAP), a method for application layer protection of the Constrained Application Protocol (CoAP), using the CBOR Object Signing and Encryption (COSE). OSCOAP provides end-to-end encryption, integrity and replay protection to CoAP payload, options, and header fields, as well as a secure message binding. OSCOAP is designed for constrained nodes and networks and can be used across intermediaries and over any layer. The use of OSCOAP is signaled with the CoAP option Object-Security, also defined in this document.

--- middle

# Introduction

The Constrained Application Protocol (CoAP) is a web application protocol, designed for constrained nodes and networks {{RFC7228}}. CoAP specifies the use of proxies for scalability and efficiency. At the same time CoAP {{RFC7252}} references DTLS {{RFC6347}} for security. CoAP proxies require DTLS to be terminated at the proxy. The proxy therefore not only has access to the data required for performing the intended proxy functionality, but is also able to eavesdrop on, or manipulate any part of the CoAP payload and metadata, in transit between client and server. The proxy can also inject, delete, or reorder packages since they are no longer protected by DTLS.

This document defines the security protocol Object Security of CoAP (OSCOAP), protecting CoAP request and responses end-to-end across intermediary nodes such as CoAP forward proxies and HTTP-to-CoAP proxies {{RFC8075}}. An analysis of end-to-end security for CoAP messages through some types of intermediary nodes is performed in {{I-D.hartke-core-e2e-security-reqs}}. In addition to the core features defined in {{RFC7252}}, OSCOAP supports Observe {{RFC7641}} and Blockwise {{RFC7959}}.

OSCOAP is designed for constrained nodes and networks and provides an in-layer security protocol for CoAP which does not depend on underlying layers. OSCOAP can be used anywhere that CoAP can be used, including unreliable transport {{RFC7228}}, reliable transport {{I-D.ietf-core-coap-tcp-tls}}, and non-IP transport {{I-D.bormann-6lo-coap-802-15-ie}}. An extension of OSCOAP may also be used to protect group communication for CoAP {{I-D.tiloca-core-multicast-oscoap}}. The use of OSCOAP does not affect the URI scheme and OSCOAP can therefore be used with any URI scheme defined for CoAP. The application decides the conditions for which OSCOAP is required. 

OSCOAP builds on CBOR Object Signing and Encryption (COSE) {{RFC8152}}, providing end-to-end encryption, integrity, replay protection, and secure message binding. A compressed version of COSE is used, see {{compression}}. The use of OSCOAP is signaled with the CoAP option Object-Security, defined in {{option}}. OSCOAP protects as much information as possible, while still allowing proxy operations. OSCOAP provides protection of CoAP payload, most options, and certain header fields. The solution transforms a CoAP message into an "OSCOAP message" before sending, and vice versa after receiving. The OSCOAP message is a CoAP message related to the original CoAP message in the following way: the original CoAP message payload (if present), options not processed by a proxy, and the request/response method (CoAP code) are protected in a COSE object. The message fields of the original messages that are encrypted are not present in the OSCOAP message, and instead the Object-Security option and the compressed COSE object are added, see {{fig-sketch}}.

~~~~~~~~~~~
Client                                            Server
   |  OSCOAP request:                               |
   |    GET example.com                             |
   |    [Header, Token, Options: {...,              |
   |     Object-Security: Compressed COSE object}]  |
   +----------------------------------------------->|
   |  OSCOAP response:                              |
   |    2.05 (Content)                              |
   |    [Header, Token, Options: {...,              |
   |     Object-Security:-},                        |
   |     Payload: Compressed COSE object]           |
   |<-----------------------------------------------+
   |                                                |
~~~~~~~~~~~
{: #fig-sketch title="Sketch of OSCOAP" artwork-align="center"}

OSCOAP may be used in very constrained settings, thanks to its small message size and the restricted code and memory requirements in addition to what is required by CoAP. OSCOAP can be combined with transport layer security such as DTLS or TLS, thereby enabling end-to-end security of e.g. CoAP payload and options, in combination with hop-by-hop protection of the entire CoAP message, during transport between end-point and intermediary node. Examples of the use of OSCOAP are given in {{examples}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}. These words may also appear in this document in lowercase, absent their normative meanings.

Readers are expected to be familiar with the terms and concepts described in CoAP {{RFC7252}}, Observe {{RFC7641}}, Blockwise {{RFC7959}}, COSE {{RFC8152}}, CBOR {{RFC7049}}, CDDL {{I-D.greevenbosch-appsawg-cbor-cddl}}, and constrained environments {{RFC7228}}.

The terms Common/Sender/Recipient Context, Master Secret/Salt, Sender ID/Key/IV, Recepient ID/Key/IV and Context IV are defined in {{context-definition}}.

# The Object-Security Option {#option}

The Object-Security option (see {{fig-option}}) indicates that OSCOAP is used to protect the CoAP request or response. The Object-Security option is critical, safe to forward, part of the cache key, and not repeatable. 

~~~~~~~~~~~
+-----+---+---+---+---+-----------------+-----------+-----------+
| No. | C | U | N | R | Name            | Format    | Length    |
+-----+---+---+---+---+-----------------+-----------+-----------|
| TBD | x |   |   |   | Object-Security | see below | see below |
+-----+---+---+---+---+-----------------+-----------+-----------+
   C = Critical,  U = Unsafe,  N = NoCacheKey,  R = Repeatable   
~~~~~~~~~~~
{: #fig-option title="The Object-Security Option" artwork-align="center"}

The option is either empty or contains a compressed COSE object (see {{cose-object}} and {{compression}}), and has no default value (except for certain CoAP codes, see below). The length of the Object-Security option is either zero or the sum of the length of the compressed COSE header, the lengths of the encrypted options and payload present in the original CoAP message, and the length of the authentication tag. Since the payload and most options are encrypted {{protected-fields}}, and the corresponding plain message fields of the original are not included in the OSCOAP message, the processing of these fields does not expand the total message size.

A successful response to a request with the Object-Security option SHALL contain the Object-Security option. A CoAP endpoint SHOULD NOT cache a response to a request with an Object-Security option, since the response is only applicable to the original client's request. The Object-Security option is included in the cache key for backward compatibility with proxies not recognizing the Object-Security option. The effect is that messages with the Object-Security option will never generate cache hits. For Max-Age processing, see {{max-age}}. 

The placement of the compressed COSE object in the OSCOAP message depends on whether the CoAP code allows payload ({{RFC7252}}, illustrated in {{fig-sketch}}):

* If the CoAP code allows payload, then the compressed COSE object is the payload of the OSCOAP message, and the Object-Security option has length zero. An endpoint receiving a CoAP message with payload, that also contains a non-empty Object-Security option SHALL treat it as malformed and reject it.

* If the CoAP code does not allow payload, then the compressed COSE object {{compression}} is the value of the Object-Security option and the length of the Object-Security option is equal to the size of the compressed COSE object. An endpoint receiving a CoAP message without payload, that also contains an empty Object-Security option SHALL treat it as malformed and reject it.

# The Security Context {#context}

OSCOAP uses COSE with an Authenticated Encryption with Additional Data (AEAD) algorithm for encrypting CoAP message data between a CoAP client and a CoAP server. An implementation supporting this specification MAY only implement the client part or MAY only implement the server part.

This specification requires that client and server establish a security context to apply to the COSE objects protecting the CoAP messages. In this section, we define the security context and how it is derived in client and server based on a common shared master secret and a key derivation function (KDF).

## Security Context Definition {#context-definition}

The security context is the set of information elements necessary to carry out the cryptographic operations in OSCOAP. For each endpoint, the security context is composed of a "Common Context", a "Sender Context", and a "Recipient Context".

The endpoints protect messages to send using the Sender Context and verify messages received using the Recipient Context, both contexts being derived from the Common Context and other data. Clients need to be able to retrieve the correct security context to use.

An endpoint uses its Sender ID (SID) to derive its Sender Context, and the other endpoint uses the same ID, now called Recipient ID (RID), to derive its Recipient Context. In communication between two endpoints, the Sender Context of one endpoint matches the Recipient Context of the other endpoint, and vice versa. Thus, the two security contexts identified by the same IDs in the two endpoints are not the same, but they are partly mirrored. Retrieval and use of the security context are shown in {{fig-context}}.

~~~~~~~~~~~
               .------------.           .------------.
               |  Common,   |           |  Common,   |
               |  Sender,   |           |  Recipient,|
               |  Recipient |           |  Sender    |
               '------------'           '------------'
                   Client                   Server
                      |                       |
Retrieve context for  | OSCOAP request:       |
 target resource      | [Token = Token1,      |
Protect request with  |  kid = SID, ...]      |
  Sender Context      +---------------------->| Retrieve context with
                      |                       |  RID = kid
                      |                       | Verify request with
                      |                       |  Recipient Context
                      | OSCOAP response:      | Protect response with
                      | [Token = Token1, ...] |  Sender Context
Retrieve context with |<----------------------+
 Token = Token1       |                       |
Verify request with   |                       |
 Recipient Context    |                       |
~~~~~~~~~~~
{: #fig-context title="Retrieval and use of the Security Context" artwork-align="center"}

The Common Context contains the following parameters:

* AEAD Algorithm (alg). The COSE AEAD algorithm to use for encryption. Its value is immutable once the security context is established.

* Key Derivation Function. The HMAC based HKDF used to derive Sender Key, Sender IV, Recipient Key, and Recipient IV.

* Master Secret. Variable length, uniformly random byte string containing the key used to derive traffic keys and IVs. Its value is immutable once the security context is established.

* Master Salt (OPTIONAL). Variable length byte string containing the salt used to derive traffic keys and IVs. Its value is immutable once the security context is established.

The Sender Context contains the following parameters:

* Sender ID. Variable length byte string identifying the Sender Context. Its value is immutable once the security context is established.

* Sender Key. Byte string containing the symmetric key to protect messages to send. Derived from Common Context and Sender ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Sender IV. Byte string containing the IV to protect messages to send. Derived from Common Context and Sender ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Sequence Number. Non-negative integer used to protect requests and observe responses to send. Used as partial IV {{RFC8152}} to generate unique nonces for the AEAD. Maximum value is determined by the AEAD Algorithm.

The Recipient Context contains the following parameters:

* Recipient ID. Variable length byte string identifying the Recipient Context. Its value is immutable once the security context is established.

* Recipient Key. Byte string containing the symmetric key to verify messages received. Derived from Common Context and Recipient ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Recipient IV. Byte string containing the IV to verify messages received. Derived from Common Context and Recipient ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Replay Window (Server only). The replay window to verify requests received.

When it is understood which context is referred to (Sender Context or Recipient Context), the term "Context IV" is used to denote the IV currently used with this context.

An endpoint may free up memory by not storing the Sender Key, Sender IV, Recipient Key, and Recipient IV, deriving them from the Common Context when needed. Alternatively, an endpoint may free up memory by not storing the Master Secret and Master Salt after the other parameters have been derived.

The endpoints MAY interchange the client and server roles while maintaining the same security context. When this happens, the former server still protects messages to send using its Sender Context, and verifies messages received using its Recipient Context. The same is also true for the former client. The endpoints MUST NOT change the Sender/Recipient ID when changing roles. In other words, changing the roles does not change the set of keys to be used.

## Derivation of Security Context Parameters {#context-derivation}

The parameters in the security context are derived from a small set of input parameters. The following input parameters SHALL be pre-established:

* Master Secret

* Sender ID 

* Recipient ID 

The following input parameters MAY be pre-established. In case any of these parameters is not pre-established, the default value indicated below is used:

* AEAD Algorithm (alg)

   - Default is AES-CCM-64-64-128 (COSE abbreviation: 12)

* Master Salt

   - Default is the empty string

* Key Derivation Function (KDF)

   - Default is HKDF SHA-256

* Replay Window Type and Size

   - Default is DTLS-type replay protection with a window size of 32 ({{RFC6347}})

All input parameters need to be known to and agreed on by both endpoints, but the replay window may be different in the two endpoints. The replay window type and size is used by the client in the processing of the Request-Tag {{I-D.amsuess-core-repeat-request-tag}}. How the input parameters are pre-established, is application specific. The ACE framework may be used to establish the necessary input parameters {{I-D.ietf-ace-oauth-authz}}. 

### Derivation of Sender Key/IV, Recipient Key/IV 

The KDF MUST be one of the HMAC based HKDF {{RFC5869}} algorithms defined in COSE. HKDF SHA-256 is mandatory to implement. The security context parameters Sender Key/IV and Recipient Key/IV SHALL be derived from the input parameters using the HKDF, which consists of the composition of the HKDF-Extract and HKDF-Expand steps ({{RFC5869}}):

~~~~~~~~~~~
   output parameter = HKDF(salt, IKM, info, L) 
~~~~~~~~~~~

where:

* salt is the Master Salt as defined above
* IKM is the Master Secret is defined above
* info is a CBOR array consisting of:

~~~~~~~~~~~ CDDL
   info = [
       id : bstr,
       alg : int,
       type : tstr,
       L : int
   ]
~~~~~~~~~~~
~~~~~~~~~~~
   * id is the Sender ID or Recipient ID

   * type is "Key" or "IV"
~~~~~~~~~~~

* L is the size of the key/IV for the AEAD algorithm used, in octets.

For example, if the algorithm AES-CCM-64-64-128 (see Section 10.2 in {{RFC8152}}) is used, the value for L is 16 for keys and 7 for IVs.

### Initial Sequence Numbers and Replay Window {#initial-replay}

The Sequence Number is initialized to 0. The supported types of replay protection and replay window length is application specific and depends on the lower layers. Default is DTLS-type replay protection with a window size of 32 initiated as described in Section 4.1.2.6 of {{RFC6347}}. 

## Requirements on the Security Context Parameters

As collisions may lead to the loss of both confidentiality and integrity, Sender ID SHALL be unique in the set of all security contexts using the same Master Secret and Master Salt. When a trusted third party assigns identifiers (e.g. using {{I-D.ietf-ace-oauth-authz}}) or by using a protocol that allows the parties to negotiate locally unique identifiers in each endpoint, the Sender IDs can be very short. Sender IDs can have any length between 0-255 bytes. Note that that the empty string is a valid Sender ID and that Sender IDs of different lengths can be used with the same Common Context. E.g. the SID with value 0x00 is different from the SID with the value 0x0000. If Sender ID uniqueness cannot be guaranteed, random Sender IDs MUST be used. Random Sender IDs MUST be long enough so that the probability of collisions is negligible.

To enable retrieval of the right Recipient Context, the Recipient ID SHOULD be unique in the sets of all Recipient Contexts used by an endpoint.

While the triple (Master Secret, Master Salt, Sender ID) MUST be unique, the same Master Salt MAY be used with several Master Secrets and the same Master Secret MAY be used with several Master Salts.

# Protected CoAP Message Fields {#protected-fields} 

OSCOAP transforms a CoAP message into an OSCOAP message, and vice versa. This section defines how the CoAP message fields are protected. Note that OSCOAP protects the CoAP Request/Response layer only, and not the Messaging layer (Section 2 of {{RFC7252}}); this means that empty CON, ACK, and RST messages are not protected. All the messages mentioned in this document refer to non-empty CON, NON, and ACK messages.

OSCOAP protects as much of the original CoAP message as possible, while still allowing proxy operations {{RFC7252}} {{RFC8075}} {{I-D.hartke-core-e2e-security-reqs}}. Message fields may either be

* Class E: encrypted and integrity protected, 
* Class I: integrity protected only, or
* Class U: unprotected.

This section outlines how the message fields are transferred, a detailed description of the processing is provided in {{processing}}. Message fields of the original CoAP message are either transferred in the header/options part of the OSCOAP message, or in the plaintext of the COSE object. Depending on which, the location of the message field in the OSCOAP message is called "outer" or "inner": 

* Inner message field: message field included in the plaintext of the COSE object of the OSCOAP message (see {{plaintext}}). The inner message fields are by definition encrypted and integrity protected by the COSE object (Class E).
* Outer message field: message field included in the header or options part of the OSCOAP message. The outer message fields are not encrypted and thus visible to an intermediary, but may be integrity protected by including the message field values in the Additional Authenticated Data (AAD) of the COSE object (see {{AAD}}). I.e. outer message fields may be Class I or Class U.

Note that, even though the message formats are slightly different, OSCOAP complies with CoAP over unreliable transport {{RFC7252}} as well as CoAP over reliable transport {{I-D.ietf-core-coap-tcp-tls}}.

## CoAP Header

Many CoAP header fields are required to be read and changed by proxies and thus cannot in general be protected between the endpoints, e.g. CoAP message layer fields such as Message ID.

The CoAP header field Code MUST be sent in clear to support RESTful processing, but MUST be integrity protected (Class I) to prevent an intermediary from changing, e.g. from GET to DELETE. The other CoAP header fields SHALL neither be integrity protected nor encrypted (Class U). All CoAP header fields are thus outer message fields.

The sending endpoint SHALL copy the header fields from the original CoAP message to the header of the OSCOAP message. The receiving endpoint SHALL copy the header fields from the OSCOAP message to the header of the decrypted CoAP message. Both sender and receiver include the CoAP header field Code in the AAD of the COSE object (see {{AAD}}). 

## CoAP Options {#coap-options}

Most options are encrypted and integrity protected (Class E), and thus inner message fields. But to allow certain proxy operations, some options have outer values, i.e. are present as options in the OSCOAP message. Certain options may have both an inner value and a potentially different outer value, where the inner value is intended for the destination endpoint and the outer value is intended for a proxy. 

A summary of how options are protected is shown in {{fig-option-protection}}. Options denoted by 'x' within each class are protected and processed in the same way, but certain options denoted by '*' require special processing.

~~~~~~~~~~~
+----+----------------+---+---+---+
| No.| Name           | E | I | U |
+----+----------------+---+---+---+
|  1 | If-Match       | x |   |   |
|  3 | Uri-Host       |   |   | x |
|  4 | ETag           | x |   |   |
|  5 | If-None-Match  | x |   |   |
|  6 | Observe        |   | * | * |
|  7 | Uri-Port       |   |   | x |
|  8 | Location-Path  | x |   |   |
| 11 | Uri-Path       | x |   |   |
| 12 | Content-Format | x |   |   |
| 14 | Max-Age        | * |   |   |
| 15 | Uri-Query      | x |   |   |
| 17 | Accept         | x |   |   |
| 20 | Location-Query | x |   |   |
| 23 | Block2         | * |   |   |
| 27 | Block1         | * |   |   |
| 28 | Size2          | * |   |   |
| 35 | Proxy-Uri      | * |   | * |
| 39 | Proxy-Scheme   |   |   | x |
| 60 | Size1          | * |   |   |
+----+----------------+---+---+---+

 E = Encrypt and Integrity Protect
 I = Integrity Protect only 
 U = Unprotected
 * = Special
~~~~~~~~~~~
{: #fig-option-protection title="Protection of CoAP Options" artwork-align="center"}

Unless specified otherwise, CoAP options not listed in {{fig-option-protection}} SHALL be encrypted and integrity protected and processed as class E options.

Specifications of new CoAP options SHOULD define how they are processed with OSCOAP. New COAP options SHOULD be of class E and SHOULD NOT have outer values unless a proxy needs to read that option value. If a certain option has both inner and outer values, the two values SHOULD NOT be the same.

### Class E Options {#class-e}

For options in class E (see {{fig-option-protection}}) the option value in the original CoAP message, if present, SHALL be encrypted and integrity protected between the endpoints. Hence the actions resulting from the use of such options is analogous to communicating in a protected manner directly with the endpoint. For example, a client using an If-Match option will not be served by a proxy.

The sending endpoint SHALL write the class E option from the original CoAP message into the plaintext of the COSE object.

Except for the special options (* in {{fig-option-protection}}), the sending endpoint SHALL NOT use the outer options of class E. However, note that an intermediary may, legitimately or not, add, change, or remove the value of an outer option.

Except for the special options, the receiving endpoint SHALL discard any outer options of class E from the OSCOAP message and SHALL write the Class E options present in the plaintext of the COSE object into the decrypted CoAP message. 

#### Max-Age {#max-age}

An inner Max-Age option, like other class E options, is used as defined in {{RFC7252}} taking into account that it is not accessible to proxies.

Since OSCOAP binds CoAP responses to requests, a cached response would not be possible to use for any other request. To avoid unnecessary caching, a server MAY add an outer Max-Age option with value zero to OSCOAP responses (see Section 5.6.1 of {{RFC7252}}). The outer Max-Age option is not integrity protected.

#### The Block Options {#block-options}

Blockwise {{RFC7959}} is an optional feature. An implementation MAY comply with {{RFC7252}} and the Object-Security option without implementing {{RFC7959}}.

The Block options (Block1, Block2, Size1, and Size2) MAY be either only inner options, only outer options or both inner and outer options. The inner and outer options are processed independently.

##### Inner Block Options

The inner Block options are used for endpoint-to-endpoint secure fragmentation of payload into blocks and protection of information about the fragmentation (block number, block size, last block). In this case, the sending CoAP endpoint fragments the CoAP message as defined in {{RFC7959}} before the message is processed by OSCOAP. The receiving CoAP endpoint first processes the OSCOAP message before processing blockwise as defined in {{RFC7959}}.

Applications using OSCOAP with inner Block options MUST specify a security policy defining a maximum unfragmented message size for inner Block options such that messages exceeding this size SHALL be fragmented by the sending endpoint. 

For blockwise request operations (using Block1) the client MUST use and process the Request-Tag as defined in Section 3 of {{I-D.amsuess-core-repeat-request-tag}}. In particular, the rules in section 3.3.1 of {{I-D.amsuess-core-repeat-request-tag}} MUST be followed, which guarantee that a specific request body is assembled only from the corresponding request blocks.

For blockwise response operations (using Block2) the server MUST use and process the ETag as defined in Section 4 of {{I-D.amsuess-core-repeat-request-tag}}. 

##### Outer Block Options

A CoAP proxy may do block fragmentation on any CoAP message (including OSCOAP messages) as defined in {{RFC7959}}, and thereby decompose it into multiple blocks using outer Block options. The outer block options are thus neither encrypted nor integrity protected. 

To allow multiple concurrent request operations to the same server (not only same resource), a CoAP proxy should use and process the Request-Tag as specified in section 3.3.2 of {{I-D.amsuess-core-repeat-request-tag}}; an OSCOAP server that supports outer Block options MUST support the Request-Tag option.

An endpoint receiving an OSCOAP message with an outer Block option SHALL first process this option according to {{RFC7959}}, until all blocks of the OSCOAP message have been received, or the cumulated message size of the blocks exceeds the maximum unfragmented message size. In the latter case the message SHALL be discarded. In the former case, the processing of the OSCOAP message continues as defined in this document.

### Class I Options {#class-i}

A Class I option is an outer option and hence visible in the options part of the OSCOAP message. Unless otherwise specified, Class I options SHALL be integrity protected between the endpoints, see ({{AAD}}). The sending endpoint SHALL encode the Class I options in the OSCOAP message as described in {{outer-options}}. 

### Class U Options {#class-u}

Options in Class U have outer values and are used to support proxy operations. Unless otherwise specified, the sending endpoint SHALL encode the Class U options in the options part of the OSCOAP message as described in {{outer-options}}.

#### Uri-Host, Uri-Port, and Proxy-Scheme 

The sending endpoint SHALL copy Uri-Host, Uri-Port, and Proxy-Scheme from the original CoAP message to the options part of the OSCOAP message. When Uri-Host, Uri-Port, or Proxy-Scheme options are present, Proxy-Uri is not used {{RFC7252}}. 

#### Proxy-Uri

Proxy-Uri, when present, is split by OSCOAP into class U options and class E options, which are processed accordingly. When Proxy-Uri is used in the original CoAP message, Uri-* are not present {{RFC7252}}.

The sending endpoint SHALL first decompose the Proxy-Uri value of the original CoAP message into the Proxy-Scheme, Uri-Host, Uri-Port, Uri-Path and Uri-Query options (if present) according to section 6.4 of {{RFC7252}}. 

Uri-Path and Uri-Query are class E options and MUST be protected and processed as if obtained from the original CoAP message, see {{class-e}}. 

The value of the Proxy-Uri option of the OSCOAP message MUST be replaced with Proxy-Scheme, Uri-Host and Uri-Port options (if present) composed according to section 6.5 of {{RFC7252}} and MUST be processed as a class U option, see {{class-u}}.

Note that replacing the Proxy-Uri value with the Proxy-Scheme and Uri-* options works by design for all CoAP URIs. OSCOAP-aware HTTP servers should not use the userinfo component of the HTTP URI (as defined in section 3.2.1. of {{RFC3986}}), so that this type of replacement is possible in the presence of CoAP-to-HTTP proxies. In other documents specifying cross-protocol proxying behavior using different URI structures, it is expected that the authors will create Uri-* options that allow decomposing the Proxy-Uri, and specify in which OSCOAP class they are.

An example of how Proxy-Uri is processed is given here. Assume that the original CoAP message contains:

* Proxy-Uri = "coap://example.com/resource?q=1"

During OSCOAP processing, Proxy-Uri is split into:

* Proxy-Scheme = "coap"
* Uri-Host = "example.com"
* Uri-Port = "5683"
* Uri-Path = "resource"
* Uri-Query = "q=1"

Uri-Path and Uri-Query follow the processing defined in {{class-e}}, and are thus encrypted and transported in the COSE object. The remaining options are composed into the Proxy-Uri included in the options part of the OSCOAP message, which has value:

* Proxy-Uri = "coap://example.com"

#### Observe {#observe}

Observe {{RFC7641}} is an optional feature. An implementation MAY support {{RFC7252}} and the Object-Security option without supporting {{RFC7641}}. The Observe option as used here targets the requirements on forwarding of {{I-D.hartke-core-e2e-security-reqs}} (Section 2.2.1.2).

In order for a proxy to support forwarding of Observe messages, there must be an Observe option present in options part of the OSCOAP message ({{RFC7641}}), so Observe must have an outer value. OCOAP aware proxies MAY look at the Partial IV value instead of the outer Observe value.

To secure the order of the notifications, the client SHALL verify that the Partial IV of a received notification is greater than any previously received Partial IV bound to the Observe request. If the verification fails, the client SHALL stop processing the response, and in the case of CON respond with an empty ACK. The client MAY ignore the outer Observe value.

The Observe option in the CoAP request may be legitimately removed by a proxy. If the Observe option is removed from a CoAP request by a proxy, then the server can still verify the request (as a non-Observe request), and produce a non-Observe response. If the OSCOAP client receives a response to an Observe request without an outer Observe value, then it MUST verify the response as a non-Observe response. (The reverse case is covered in the verification of the response {{processing}}.)

### Outer Options in the OSCOAP Message {#outer-options}

All options with outer values present in the OSCOAP message, including the Object-Security option, SHALL be encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included outer option value. 

## CoAP Payload

The CoAP Payload SHALL be encrypted and integrity protected (Class E), and thus is an inner message field.

The sending endpoint writes the payload of the original CoAP message into the plaintext of the COSE object.

The receiving endpoint verifies and decrypts the COSE object, and recreates the payload of the original CoAP message.

# The COSE Object {#cose-object}

This section defines how to use COSE {{RFC8152}} to wrap and protect data in the original CoAP message. OSCOAP uses the untagged COSE_Encrypt0 structure with an Authenticated Encryption with Additional Data (AEAD) algorithm. The key lengths, IV lengths, nonce lenght, and maximum sequence number are algorithm dependent.
 
The AEAD algorithm AES-CCM-64-64-128 defined in Section 10.2 of {{RFC8152}} is mandatory to implement. For AES-CCM-64-64-128 the length of Sender Key and Recipient Key is 128 bits, the length of nonce, Sender IV, and Recipient IV is 7 bytes. The maximum Sequence Number is specified in {{sec-considerations}}.

We denote by Plaintext the data that is encrypted and integrity protected, and by Additional Authenticated Data (AAD) the data that is integrity protected only.

The COSE Object SHALL be a COSE_Encrypt0 object with fields defined as follows

- The "protected" field is empty.

- The "unprotected" field includes:

   * The "Partial IV" parameter. The value is set to the Sequence Number. The Partial IV SHALL be of minimum length needed to encode the sequence number. This parameter SHALL be present in requests. In case of Observe ({{observe}}) the Partial IV SHALL be present in responses, and otherwise the Partial IV SHALL NOT be present in responses.

   * The "kid" parameter. The value is set to the Sender ID (see {{context}}). This parameter SHALL be present in requests and SHALL NOT be present in responses.

-  The "ciphertext" field is computed from the secret key (Sender Key or Reciepient Key), Nonce (see {{nonce}}), Plaintext (see {{plaintext}}), and the Additional Authenticated Data (AAD) (see {{AAD}}) following Section 5.2 of {{RFC8152}}.

The encryption process is described in Section 5.3 of {{RFC8152}}.


## Nonce {#nonce}

The nonce is constructed as described in Section 3.1 of {{RFC8152}}, i.e. by padding the partial IV (Sequence Number in network byte order) with zeroes and XORing it with the Context IV (Sender IV or Recipient IV), with the following addition: The most significant bit in the first byte of the Context IV SHALL be flipped for responses, in case there is a single response (not Observe). In this way, the partial IV can be reused for the corresponding responses, which reduces the size of the response. For detailed processing instructions, see {{processing}}. 

## Plaintext {#plaintext}

The Plaintext is formatted as a CoAP message without Header (see {{fig-plaintext}}) consisting of:

- all Class E option values {{class-e}} present in the original CoAP message (see {{coap-options}}). The options are encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included Class E option; and

- the Payload of original CoAP message, if present, and in that case prefixed by the one-byte Payload Marker (0xFF).

~~~~~~~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Class E options (if any) ...                             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...                        
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 (only if there 
   is payload)
~~~~~~~~~~~
{: #fig-plaintext title="Plaintext" artwork-align="center"}

## Additional Authenticated Data {#AAD}

The external_aad SHALL be a CBOR array as defined below:

~~~~~~~~~~~ CDDL
external_aad = [
   version : uint,
   code : uint,
   options : bstr,
   alg : int,
   request_kid : bstr,
   request_piv : bstr
]
~~~~~~~~~~~

where:

- version: contains the OSCOAP version number. Implementations of this specification MUST set this field to 1. Other values are reserved for future versions.

- code: contains is the CoAP Code of the original CoAP message, as defined in Section 3 of {{RFC7252}}.

- options: contains the Class I options {{class-i}} present in the original CoAP message encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included class I option.

- alg: contains the AEAD Algorithm from the security context used for the exchange (see {{context-definition}}).

- request_kid: contains the value of the 'kid' in the COSE object of the request (see Section 5).

- request_piv: contains the value of the 'Partial IV' in the COSE object of the request (see Section 5).

# Sequence Numbers, Replay, Message Binding, and Freshness {#sequence-numbers}

Sequence numbers and replay window are initialized as defined in {{initial-replay}}.

## AEAD Nonce Uniqueness {#nonce-uniqueness}

An AEAD nonce MUST NOT be used more than once per AEAD key. In order to assure unique nonces, each Sender Context contains a Sequence Number used to protect requests, and - in case of Observe - responses. The maximum sequence number is algorithm dependent, see {{sec-considerations}}. If the Sequence Number exceeds the maximum sequence number, the endpoint MUST NOT process any more messages with the given Sender Context. The endpoint SHOULD acquire a new security context (and consequently inform the other endpoint) before this happens. The latter is out of scope of this document.

## Replay Protection

In order to protect from replay of requests, the server's Recipient Context contains a Replay Window. A server SHALL verify that a Partial IV received in the COSE object has not been received before in the Recipient Context. If this verification fails and the message received is a CON message, the server SHALL respond with a 5.03 Service Unavailable error message with the option Max-Age set to 0. The diagnostic payload MAY contain the "Replay protection failed" string.

The size and type of the Replay Window depends on the use case and lower protocol layers. In case of reliable and ordered transport from endpoint to endpoint, the server MAY just store the last received Partial IV and require that newly received Partial IVs equals the last received Partial IV + 1.

Reponses are protected against replay as they are cryptographically bound to the request. In the case of Observe, only strictly increasing Partial IVs are accepted. If this verification fails and the message received is a CON message, the client SHALL respond with an empty ACK and stop processing the response.

## Sequence Number and Replay Window State {#replay-state}

To prevent reuse of the Nonce with the same key, or from accepting replayed messages, a node needs to handle the situation of suddenly losing sequence number and replay window state in RAM, e.g. as a result of a reboot.

After boot, a node MAY reject to use existing security contexts from before it booted and MAY establish a new security context with each party it communicates, e.g. using ACE {{I-D.ietf-ace-oauth-authz}}. However, establishing a fresh security context may have a non-negligible cost in terms of e.g. power consumption.

If a stored security context is to be used after reboot, then the node MUST NOT reuse a previous Sequence Number and MUST NOT accept previously accepted messages. 

### The Basic Case

To prevent reuse of Sequence Number, the node MAY perform the following procedure during normal operations:

* Before sending a message, the client stores in persistent memory a sequence number associated to the stored security context higher than any sequence number which has been or are being sent using this security context. After boot, the client does not use any lower sequence number in a request than what was persistently stored with that security context.

   * Storing to persistent memory can be costly. Instead of storing a sequence number for each request, the client may store Seq + K to persistent memory every K requests, where Seq is the current sequence number and K > 1. This is a trade-off between the number of storage operations and efficient use of sequence numbers.

To prevent accepting replay of previously received messages, the node MAY perform the following procedure:

* After boot, before verifying a message using a security context stored before boot, the server synchronizes the replay window so that no old messages are being accepted. The server uses the Repeat option {{I-D.amsuess-core-repeat-request-tag}} for synchronizing the replay window: For each stored security context, the first time after boot the server receives an OSCOAP request, it generates a pseudo-random nonce and responds with the Repeat option set to the nonce as described in {{I-D.amsuess-core-repeat-request-tag}}. If the server receives a repeated OSCOAP request containing the Repeat option and the same nonce, and if the server can verify the request, then the sequence number obtained in the repeated message is set as the lower limit of the replay window.

### The Observe Case

To prevent reuse of Sequence Number in case of Observe, the node MAY perform the following procedure during normal operations:

* Before sending a notification, the server stores in persistent memory a sequence number associated to the stored security context higher than any sequence number for which a notification has been or are being sent using this security context. After boot, the server does not use any lower sequence number in an Observe response than what was persistently stored with that security context. 

   * Storing to persistent memory can be costly. Instead of storing a sequence number for each notification, the server may store Seq + K to persistent memory every K requests, where Seq is the current sequence number and K > 1. This is a trade-off between the number of storage operations and efficient use of sequence numbers.

Note that a client MAY continue an ongoing observation after reboot using a stored security context. With Observe, the client can only verify the order of the notifications, as they may be delayed. If the client wants to synchronize with a server resource it MAY restart an observation.

## Freshness

For responses without Observe, OSCOAP provides absolute freshness. For requests, and responses with Observe, OSCOAP provides relative freshness in the sense that the sequence numbers allow a recipient to determine the relative order of messages.

For applications having stronger demands on freshness (e.g. control of actuators), OSCOAP needs to be augmented with mechanisms providing absolute freshness {{I-D.amsuess-core-repeat-request-tag}}. 

## Delay and Mismatch Attacks

In order to prevent response delay and mismatch attacks {{I-D.mattsson-core-coap-actuators}} from on-path attackers and compromised proxies, OSCOAP binds responses to the request by including the request's ID (Sender ID or Recipient ID) and sequence number in the AAD of the response. The server therefore needs to store the request's ID (Sender ID or Recipient ID) and sequence number until all responses have been sent.

# Processing {#processing}

This section describes the OSCOAP message processing. An illustration of the nonce generation used in the processing is given in {{nonce-generation}}.

## Protecting the Request

Given a CoAP request, the client SHALL perform the following steps to create an OSCOAP request:

1. Retrieve the Sender Context associated with the target resource.

2. Compose the Additional Authenticated Data, as described in {{cose-object}}.

3. Compose the AEAD nonce by XORing the Context IV (Sender IV) with the partial IV (Sequence Number in network byte order). Then increment the Sequence Number by one.

4. Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in {{compression}}.

5. Format the OSCOAP message according to {{protected-fields}}. The Object-Security option is added, see {{outer-options}}.

6. Store the association Token - Security Context. The client SHALL be able to find the Recipient Context from the Token in the response.

## Verifying the Request

A server receiving a request containing the Object-Security option SHALL perform the following steps:

1. Process outer Block options according to {{RFC7959}}, until all blocks of the request have been received, see {{block-options}}.

2. Decompress the COSE Object ({{compression}}) and retrieve the Recipient Context associated with the Recipient ID in the 'kid' parameter. If the request is a CON message, and:

   * either the decompression or the COSE message fails to decode, the server SHALL respond with a 4.02 Bad Option error message. The diagnostic payload SHOULD contain the string "Failed to decode COSE".
   
   * the server fails to retrieve a Recipient Context with Recipient ID corresponding to the 'kid' parameter received, the server SHALL respond with a 4.01 Unauthorized error message. The diagnostic payload MAY contain the string "Security context not found".

If the request is a NON message and either the decompression or the COSE message fails to decode, or the server fails to retrieve a Recipient Context with Recipient ID corresponding to the 'kid' parameter received, then the server SHALL stop processing the request.

3. Verify the Sequence Number in the 'Partial IV' parameter, as described in {{sequence-numbers}}.

4. Compose the Additional Authenticated Data, as described in {{cose-object}}.

5. Compose the AEAD nonce by XORing the Context IV (Recipient IV) with the padded 'Partial IV' parameter, received in the COSE Object.

6. Decrypt the COSE object using the Recipient Key.

   * If decryption fails, the server MUST stop processing the request and, if the request is a CON message, the server MUST respond with a 4.00 Bad Request error message. The diagnostic payload MAY contain the "Decryption failed" string.

   * If decryption succeeds, update the Recipient Replay Window, as described in {{sequence-numbers}}.

7. Add decrypted options and payload to the decrypted request, processing the E options as described in ({{protected-fields}}). The Object-Security option is removed.

8. The decrypted CoAP request is processed according to {{RFC7252}}

## Protecting the Response

Given a CoAP response, the server SHALL perform the following steps to create an OSCOAP response:

1. Retrieve the Sender Context in the Security Context used to verify the request.

2. Compose the Additional Authenticated Data, as described in {{cose-object}}.

3. Compose the AEAD nonce

   * If Observe is not used, compose the AEAD nonce by XORing the Context IV (Sender IV with the most significant bit in the first byte flipped) with the padded Partial IV parameter from the request.
 
   * If Observe is used, compose the AEAD nonce by XORing the Context IV (Sender IV) with the Partial IV of the response (Sequence Number in network byte order). Then increment the Sequence Number by one.

4. Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in {{compression}}.

5. Format the OSCOAP message according to {{protected-fields}}. The Object-Security option is added, see {{outer-options}}.

## Verifying the Response

A client receiving a response containing the Object-Security option SHALL perform the following steps:

1. Process outer Block options according to {{RFC7959}}, until all blocks of the OSCOAP message have been received, see {{block-options}}.

2. Retrieve the Recipient Context associated with the Token. Decompress the COSE Object ({{compression}}). If the response is a CON message and either the decompression or the COSE message fails to decode, then the client SHALL send an empty ACK back and stop processing the response.
If the response is a NON message and any of the previous conditions appear, then the client SHALL simply stop processing the response.

<!--
there is no way to tell the server it made a mistake. we send an ack back to stop retransmission
 -->

3. For Observe notifications, verify the Sequence Number in the 'Partial IV' parameter as described in {{sequence-numbers}}. If the client receives a notification for which no Observe request was sent, the client SHALL stop processing the response and, in the case of CON send an empty ACK back.

4. Compose the Additional Authenticated Data, as described in {{cose-object}}.

5. Compose the AEAD nonce

      * If the Observe option is not present in the response, compose the AEAD nonce by XORing the Context IV (Recipient IV with the most significant bit in the first byte flipped) with the padded Partial IV parameter from the request.
 
      * If the Observe option is present in the response, compose the AEAD nonce by XORing the Context IV (Recipient IV) with the padded Partial IV parameter from the response.

5. Decrypt the COSE object using the Recipient Key.

   * If decryption fails, the client MUST stop processing the response and, if the response is a CON message, the client MUST respond with an empty ACK back.

   * If decryption succeeds and Observe is used, update the Recipient Replay Window, as described in {{sequence-numbers}}.

6. Add decrypted options or payload to the decrypted response overwriting any outer E options (see {{protected-fields}}). The Object-Security option is removed.

   * If Observe is used, replace the Observe value with the 3 least significant bytes in the sequence number.
   
7. The decrypted CoAP response is processed according to {{RFC7252}}

## Nonce generation examples {#nonce-generation}

This section illustrates the nonce generation in the different processing steps. Assume that:

* Endpoint A has the following security context parameters: Sender Key=K1, Sender IV=IV1, Partial IV=PIV1 and Recipient Key=K2, Recipient IV=IV2, Partial IV=PIV2.

* Endpoint B has the following security context parameters: Sender Key=K2, Sender IV=IV2, Partial IV=PIV2 and Recipient Key=K1, Recipient IV=IV1, Partial IV=PIV1.

The examples below illustrate the key and nonce used with the given parameters above.

Example 1. Endpoint A as client and endpoint B as server. 

* Example 1a. Ordinary request/response.

    * Endpoint A sends a request, which is verified by Endpoint B: key=K1, nonce=IV1 XOR PIV1. 

    * Endpoint B sends a response, which is verified by Endpoint A: key=K2, nonce=BF(IV2) XOR PIV1, where BF(.) means that the most significant bit in the first byte is flipped.

* Example 1b. Observe.

   * Endpoint A sends a request, which is verified by Endpoint B: key=K1, nonce=IV1 XOR PIV1. 

   * Endpoint B sends a notification, which is verified by Endpoint A: key=K2, nonce=IV2 XOR PIV2.

Example 2. Endpoint B as client and endpoint A as server. 

* Example 2a. Ordinary request/response.

   * Endpoint B sends a request, which is verified by Endpoint A: key=K2, nonce=IV2 XOR PIV2. 

   * Endpoint A sends a response, which is verified by Endpoint B: key=K1, nonce=BF(IV1) XOR PIV2, where BF(.) means that the most significant bit in the first byte is flipped.

* Example 2b. Observe.

   * Endpoint B sends a request, which is verified by Endpoint A: key=K2, nonce=IV2 XOR PIV2. 

   * Endpoint A sends a notification, which is verified by Endpoint B: key=K1, nonce=IV1 XOR PIV1.

Note that endpoint A always uses key K1 for encrypting and K2 for verification, and conversely for endpoint B.

# OSCOAP Compression {#compression}

The Concise Binary Object Representation (CBOR) {{RFC7049}} combines very small message sizes with extensibility. The CBOR Object Signing and Encryption (COSE) {{RFC8152}} uses CBOR to create compact encoding of signed and encrypted data. COSE is however constructed to support a large number of different stateless use cases, and is not fully optimized for use as a stateful security protocol, leading to a larger than necessary message expansion. In this section, we define a simple stateless compression mechanism for OSCOAP, which significantly reduces the per-packet overhead.

## Encoding of the Object-Security Option

The value of the Object-Security option SHALL be encoded as follows:

* The first byte encodes a set of flags and the length of the Partial IV parameter.
    - The three least significant bits encode the Partial IV size n. If their value is 0, the Partial IV is not present in the compressed message.
    - The fourth least significant bit k is set to 1 if the kid is present in the compressed message.
    - The fifth-eighth least significant bits (= most significant half-byte) are reserved and SHALL be set to zero when not in use.
* The following n bytes encode the value of the Partial IV, if the Partial IV is present (n > 0).
* The following 1 byte encodes the kid size m, if the kid is present (k = 1). 
* The following m bytes encode the value of the kid, if the kid is present (k = 1).
* The remaining bytes encode the ciphertext.

~~~~~~~~~~~
 7 6 5 4 3 2 1 0   
+-+-+-+-+-+-+-+-+  k: kid flag bit
|0 0 0 0|k|  n  |  n: Partial IV size (3 bits)
+-+-+-+-+-+-+-+-+
~~~~~~~~~~~

The presence of Partial IV and kid in requests and responses is specified in {{cose-object}}, and summarized in {{fig-byte-flag}}.

~~~~~~~~~~~
+--------------------------+-----+-----+
|                          |  k  |  n  |
+--------------------------+-----+-----+
| Request                  |  1  | > 0 |
| Response without Observe |  0  |   0 |
| Response with Observe    |  0  | > 0 |
+--------------------------+-----+-----+
~~~~~~~~~~~
{: #fig-byte-flag title="Flag byte for OSCOAP compression" artwork-align="center"}

## Compression Examples

This section provides examples of COSE Objects before and after OSCOAP compression.

### Example: Request

Before compression:

~~~~~~~~~~~
[
h'',
{ 4:h'25', 6:h'05' },
h'aea0155667924dff8a24e4cb35b9'
]

0x83 40 a2 04 41 25 06 41 05 4e ae a0 15 56 67 92
4d ff 8a 24 e4 cb 35 b9 (24 bytes)
~~~~~~~~~~~

After compression:

First byte: 0b00001001 = 0x09

~~~~~~~~~~~
0x09 05 01 25 ae a0 15 56 67 92 4d ff 8a 24 e4 cb
35 b9 (18 bytes)
~~~~~~~~~~~

### Example: Response (without Observe)

Before compression:

~~~~~~~~~~~
[
h'',
{},
h'aea0155667924dff8a24e4cb35b9'
]

0x83 40 a0 4e ae a0 15 56 67 92 4d ff 8a 24 e4 cb
35 b9 (18 bytes)
~~~~~~~~~~~

After compression:

First byte: 0b00000000 = 0x00

~~~~~~~~~~~
0x00 ae a0 15 56 67 92 4d ff 8a 24 e4 cb 35 b9
(15 bytes)
~~~~~~~~~~~

### Example: Response (with Observe)

Before compression:

~~~~~~~~~~~
[
h'',
{ 6:h'07' },
h'aea0155667924dff8a24e4cb35b9'
]

0x83 40 a1 06 41 07 4e ae a0 15 56 67 92 4d ff
8a 24 e4 cb 35 b9 (21 bytes)
~~~~~~~~~~~

After compression:

First byte: 0b00000001 = 0x01

~~~~~~~~~~~
0x01 07 ae a0 15 56 67 92 4d ff 8a 24 e4 cb 35 b9
(16 bytes)
~~~~~~~~~~~

# Web Linking

The use of OSCOAP MAY be indicated by a target attribute "osc" in a web link {{RFC5988}} to a CoAP resource. This attribute is a hint indicating that the destination of that link is to be accessed using OSCOAP. Note that this is simply a hint, it does not include any security context material or any other information required to run OSCOAP. 

A value MUST NOT be given for the "osc" attribute; any present value MUST be ignored by parsers. The "osc" attribute MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers.

# HTTP-CoAP Mapping

As requested in Section 1 of {{RFC8075}}, this section describes the
HTTP mapping for the OSCOAP protocol extension of CoAP.

The presence and content of the Object-Security option, both in requests and
responses, is expressed in a HTTP header field named Object-Security in the
mapped request or response. The value of the field is the value of the
CoAP Object-Security option in base64url encoding without padding (see
{{RFC7515}} Appendix C for implementation notes for this encoding).

In addition, whenever the Object-Security field is present, the protected
message's code is expressed in a HTTP header field named CoAP-Code in dotted
code number notation with leading zero. When converting an HTTP request or
response to CoAP, the code in the CoAP-Code field gets used in the CoAP
message, and the response code mapping rules ({{RFC8075}} Section 7)
are not applied.

Invalid base64url data, the absence of the CoAP-Code field or a CoAP-Code field
value that cannot be expressed as a CoAP code byte constitute an error, and
MUST result in a 4.02 Bad Option or 400 Bad Request, depending on the protocol
used in the request. If any mapper receives an Object-Security header, it MUST
verify that the code classes match to the extent of being a request (CoAP code
class 0 mapped to an HTTP request) or a response (CoAP code classes 1-5 mapped
to a HTTP response) code.

Example:

~~~~~~~~~~~
[HTTP request -- Before object security processing]

  GET /hc/coap://device.local/orders HTTP/1.1
  Host: proxy.local

[HTTP request -- HTTP Client to Proxy]

  GET /hc/coap://device.local/ HTTP/1.1
  Host: proxy.local
  CoAP-Code: 0.01
  Object-Security: CQcBE2H3D9KXsQ

[CoAP request -- Proxy to CoAP Server]

  GET /
  Uri-Host: device.local
  Object-Security: 09 07 01 13 61 f7 0f d2 97 b1 [binary]

[CoAP response -- CoAP Sever to Proxy]

  2.05 Content
  Object-Security: [empty]
  Payload: 00 31 d1 fc f6 70 fb 0c 1d d5 ... [binary]

[HTTP response -- Proxy to HTTP Client]

  HTTP/1.1 200 OK
  Object-Security: [empty]
  CoAP-Code: 2.05
  Body: 00 31 d1 fc f6 70 fb 0c 1d d5 ... [binary]

[HTTP response -- After object security processing]

  HTTP/1.1 200 OK
  Body: Exterminate! Exterminate!
~~~~~~~~~~~

# Security Considerations {#sec-considerations}

In scenarios with intermediary nodes such as proxies or brokers, transport layer security such as DTLS only protects data hop-by-hop. As a consequence, the intermediary nodes can read and modify information. The trust model where all intermediate nodes are considered trustworthy is problematic, not only from a privacy perspective, but also from a security perspective, as the intermediaries are free to delete resources on sensors and falsify commands to actuators (such as "unlock door", "start fire alarm", "raise bridge"). Even in the rare cases, where all the owners of the intermediary nodes are fully trusted, attacks and data breaches make such an architecture brittle.

DTLS protects hop-by-hop the entire CoAP message, including header, options, and payload. OSCOAP protects end-to-end the payload, and all information in the options and header, that is not required for proxy operations (see {{protected-fields}}). DTLS and OSCOAP can be combined, thereby enabling end-to-end security of CoAP payload, in combination with hop-by-hop protection of the entire CoAP message, during transport between end-point and intermediary node. The CoAP message layer, however, cannot be protected end-to-end through intermediary devices since the parameters Type and Message ID, as well as Token and Token Length may be changed by a proxy.

The use of COSE to protect CoAP messages as specified in this document requires an established security context. The method to establish the security context described in {{context-derivation}} is based on a common shared secret material in client and server, which may be obtained e.g. by using the ACE framework {{I-D.ietf-ace-oauth-authz}}. An OSCOAP profile of ACE is described in {{I-D.seitz-ace-oscoap-profile}}.

The mandatory-to-implement AEAD algorithm AES-CCM-64-64-128 is selected for broad applicability in terms of message size (2^64 blocks) and maximum number of messages (2^56). Compatibility with CCM* is achieved by using the algorithm AES-CCM-16-64-128 {{RFC8152}}.

Most AEAD algorithms require a unique nonce for each message, for which the sequence numbers in the COSE message field "Partial IV" is used. If the recipient accepts any sequence number larger than the one previously received, then the problem of sequence number synchronization is avoided. With reliable transport, it may be defined that only messages with sequence number which are equal to previous sequence number + 1 are accepted. The alternatives to sequence numbers have their issues: very constrained devices may not be able to support accurate time, or to generate and store large numbers of random nonces. The requirement to change key at counter wrap is a complication, but it also forces the user of this specification to think about implementing key renewal.

The maximum sequence number to guarantee nonce uniqueness ({{nonce-uniqueness}}) is dependent on the AEAD algorithm. The maximum sequence number SHALL be 2^(min(nonce length in bits, 56) - 1) - 1, or any algorithm specific lower limit. The "-1" in the exponent stems from the same partial IV and flipped bit of IV ({{cose-object}}) is used in request and response. The compression mechanism ({{compression}}) assumes that the partial IV is 56 bits or less (which is the reason for min(,) in the exponent).

The inner block options enable the sender to split large messages into OSCOAP-protected blocks such that the receiving node can verify blocks before having received the complete message. The outer block options allow for arbitrary proxy fragmentation operations that cannot be verified by the endpoints, but can by policy be restricted in size since the encrypted options allow for secure fragmentation of very large messages. A maximum message size (above which the sending endpoint fragments the message and the receiving endpoint discards the message, if complying to the policy) may be obtained as part of normal resource discovery.

Applications need to use a padding scheme if the content of a message can be determined solely from the length of the payload. As an example, the strings "YES" and "NO" even if encrypted can be distinguished from each other as there is no padding supplied by the current set of encryption algorithms. Some information can be determined even from looking at boundary conditions. An example of this would be returning an integer between 0 and 100 where lengths of 1, 2 and 3 will provide information about where in the range things are. Three different methods to deal with this are: 1) ensure that all messages are the same length. For example, using 0 and 1 instead of 'yes' and 'no'. 2) Use a character which is not part of the responses to pad to a fixed length. For example, pad with a space to three characters. 3) Use the PKCS #7 style padding scheme where m bytes are appended each having the value of m. For example, appending a 0 to "YES" and two 1's to "NO". This style of padding means that all values need to be padded.

# Privacy Considerations

Privacy threats executed through intermediate nodes are considerably reduced by means of OSCOAP. End-to-end integrity protection and encryption of CoAP payload and all options that are not used for proxy operations, provide mitigation against attacks on sensor and actuator communication, which may have a direct impact on the personal sphere.

The unprotected options ({{fig-option-protection}}) may reveal privacy sensitive information. In particular Uri-Host SHOULD NOT contain privacy sensitive information. 

CoAP headers sent in plaintext allow for example matching of CON and ACK (CoAP Message Identifier), matching of request and responses (Token) and traffic analysis.

Using the mechanisms described in {{replay-state}} reveals when a device goes through a reboot. This can be mitigated by the device storing the precise state of sender sequence number and recipient replay window on a clean shutdown.

# IANA Considerations

Note to RFC Editor: Please replace all occurrences of "[[this document\]\]" with the RFC number of this specification.

## CoAP Option Numbers Registry 

The Object-Security option is added to the CoAP Option Numbers registry:

~~~~~~~~~~~
+--------+-----------------+-------------------+
| Number | Name            | Reference         |
+--------+-----------------+-------------------+
|  TBD   | Object-Security | [[this document]] |
+--------+-----------------+-------------------+
~~~~~~~~~~~
{: artwork-align="center"}

## Header Field Registrations

The HTTP header field CoAP-Code field is added to the Message Headers registry:

~~~~~~~~~~~
+-------------------+----------+----------+-------------------+
| Header Field Name | Protocol | Status   | Reference         |
+-------------------+----------+----------+-------------------+
| CoAP-Code         | http     | standard | [[this document]] |
+-------------------+----------+----------+-------------------+
~~~~~~~~~~~
{: artwork-align="center"}

# Acknowledgments

The following individuals provided input to this document: Christian Amsüss, Tobias Andersson, Carsten Bormann, Joakim Brorsson, Thomas Fossati, Martin Gunnarsson, Klaus Hartke, Jim Schaad, Dave Thaler, Marco Tiloca, and Mališa Vučinić.

Ludwig Seitz and Göran Selander worked on this document as part of the CelticPlus project CyberWI, with funding from Vinnova.

--- back

# Test Vectors

TODO: This section needs to be updated.

# Examples {#examples}

This section gives examples of OSCOAP. The message exchanges are made, based on the assumption that there is a security context established between client and server. For simplicity, these examples only indicate the content of the messages without going into detail of the COSE message format.

## Secure Access to Sensor

This example targets the scenario in Section 3.1 of {{I-D.hartke-core-e2e-security-reqs}} and illustrates a client requesting the alarm status from a server.

~~~~~~~~~~~
Client  Proxy  Server
   |      |      |
   +----->|      |            Code: 0.01 (GET)
   | GET  |      |           Token: 0x8c
   |      |      | Object-Security: [kid:5f, Partial IV:42,
   |      |      |                   {Uri-Path:"alarm_status"}]
   |      |      |         Payload: -
   |      |      |
   |      +----->|            Code: 0.01 (GET)
   |      | GET  |           Token: 0x7b
   |      |      | Object-Security: [kid:5f, Partial IV:42,
   |      |      |                   {Uri-Path:"alarm_status"}]
   |      |      |         Payload: -
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0x7b
   |      |      | Object-Security: -
   |      |      |         Payload: [{"OFF"}]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x8c
   |      |      | Object-Security: -
   |      |      |         Payload: [{"OFF"}]
   |      |      |
~~~~~~~~~~~
{: #fig-alarm title="Secure Access to Sensor. Square brackets [ ... ] indicate a COSE object. Curly brackets { ... \} indicate encrypted data." artwork-align="center"}

Since the method (GET) doesn't allow payload, the Object-Security option carries the COSE object as its value. Since the response code (Content) allows payload, the COSE object is carried as the CoAP payload.

The COSE header of the request contains an identifier (5f), indicating which security context was used to protect the message and a Partial IV (42). The option Uri-Path ("alarm_status") and payload ("OFF") are encrypted.

The server verifies that the Partial IV has not been received before. The client verifies that the response is bound to the request.

## Secure Subscribe to Sensor

This example targets the scenario in Section 3.2 of {{I-D.hartke-core-e2e-security-reqs}} and illustrates a client requesting subscription to a blood sugar measurement resource (GET /glucose), first receiving the value 220 mg/dl and then a second value 180 mg/dl.

~~~~~~~~~~~
Client  Proxy  Server
   |      |      |
   +----->|      |            Code: 0.01 (GET)
   | GET  |      |           Token: 0x83
   |      |      |         Observe: 0
   |      |      | Object-Security: [kid:ca, Partial IV:15,
   |      |      |                   {Uri-Path:"glucose"}]
   |      |      |         Payload: -
   |      |      |
   |      +----->|            Code: 0.01 (GET)
   |      | GET  |           Token: 0xbe
   |      |      |         Observe: 0
   |      |      | Object-Security: [kid:ca, Partial IV:15,
   |      |      |                   {Uri-Path:"glucose"}]
   |      |      |         Payload: -
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0xbe
   |      |      |         Observe: 7
   |      |      | Object-Security: -
   |      |      |         Payload: [Partial IV:32,
   |      |      |                   {Content-Format:0, "220"}]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x83
   |      |      |         Observe: 7
   |      |      | Object-Security: -
   |      |      |         Payload: [Partial IV:32,
   |      |      |                   {Content-Format:0, "220"}]
  ...    ...    ...
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0xbe
   |      |      |         Observe: 8
   |      |      | Object-Security: -
   |      |      |         Payload: [Partial IV:36,
   |      |      |                   {Content-Format:0, "180"}]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x83
   |      |      |         Observe: 8
   |      |      | Object-Security: -
   |      |      |         Payload: [Partial IV:36,
   |      |      |                   {Content-Format:0, "180"}]
   |      |      |
~~~~~~~~~~~
{: #fig-blood-sugar title="Secure Subscribe to Sensor. Square brackets [ ... ] indicate a COSE object. Curly brackets { ... \} indicate encrypted data." artwork-align="center"}

Since the method (GET) doesn't allow payload, the Object-Security option carries the COSE object as its value. Since the response code (Content) allows payload, the COSE object is carried as the CoAP payload.

The COSE header of the request contains an identifier (ca), indicating the security context used to protect the message and a Partial IV (15). The COSE headers of the responses contains Partial IVs (32 and 36). The options Content-Format (0) and the payload ("220" and "180"), are encrypted. The Observe option is not protected.

The server verifies that the Partial IV has not been received before. The client verifies that the responses are bound to the request and that the Partial IVs are greater than any Partial IV previously received in a response bound to the request.

--- fluff
