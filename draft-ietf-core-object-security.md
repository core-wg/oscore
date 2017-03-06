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
        street: Färögatan 6
        code: SE-164 80 Stockholm
        country: SWEDEN
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        street: Färögatan 6
        code: SE-164 80 Stockholm
        country: SWEDEN
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Färögatan 6
        code: SE-164 80 Stockholm
        country: SWEDEN
        email: francesca.palombini@ericsson.com
      -
        ins: L. Seitz
        name: Ludwig Seitz
        org: SICS Swedish ICT
        street: Scheelevagen 17
        code: SE-223 70 Lund
        country: SWEDEN
        email: ludwig@sics.se

normative:

  I-D.ietf-cose-msg:
  RFC2119:
  RFC5869:
  RFC6347:
  RFC7049:
  RFC7252:
  RFC7641:
  RFC7959:
  
informative:

  I-D.selander-ace-cose-ecdhe:
  I-D.hartke-core-e2e-security-reqs:
  I-D.mattsson-core-coap-actuators:
  I-D.bormann-6lo-coap-802-15-ie:
  I-D.ietf-ace-oauth-authz:
  I-D.seitz-ace-oscoap-profile:
  I-D.ietf-core-coap-tcp-tls:
  I-D.tiloca-core-multicast-oscoap:
  I-D.greevenbosch-appsawg-cbor-cddl:
  RFC7228:

--- abstract

This memo defines Object Security of CoAP (OSCOAP), a method for application layer protection of the Constrained Application Protocol (CoAP), using the CBOR Object Signing and Encryption (COSE). OSCOAP provides end-to-end encryption, integrity and replay protection to CoAP payload, options, and header fields, as well as a secure message binding. OSCOAP is designed for constrained nodes and networks and can be used across intermediaries and over any layer. The use of OSCOAP is signaled with the CoAP option Object-Security, also defined in this memo.

--- middle

# Introduction {#intro}

The Constrained Application Protocol (CoAP) is a web application protocol, designed for constrained nodes and networks {{RFC7228}}. CoAP specifies the use of proxies for scalability and efficiency. At the same time CoAP {{RFC7252}} references DTLS {{RFC6347}} for security. Proxy operations on CoAP messages require DTLS to be terminated at the proxy. The proxy therefore not only has access to the data required for performing the intended proxy functionality, but is also able to eavesdrop on, or manipulate any part of the CoAP payload and metadata, in transit between client and server. The proxy can also inject, delete, or reorder packages without being protected or detected by DTLS.

This memo defines Object Security of CoAP (OSCOAP), a data object based security protocol, protecting CoAP message exchanges end-to-end, across intermediary nodes. An analysis of end-to-end security for CoAP messages through intermediary nodes is performed in {{I-D.hartke-core-e2e-security-reqs}}, this specification addresses the forwarding case. In addition to the core features defined in {{RFC7252}}, OSCOAP supports Observe {{RFC7641}} and Blockwise {{RFC7959}}.

OSCOAP is designed for constrained nodes and networks and provides an in-layer security protocol for CoAP which does not depend on underlying layers. OSCOAP can be used anywhere that CoAP can be used, including unreliable transport {{RFC7228}}, reliable transport {{I-D.ietf-core-coap-tcp-tls}}, and non-IP transport {{I-D.bormann-6lo-coap-802-15-ie}}. OSCOAP may also be used to protect group communication for CoAP {{I-D.tiloca-core-multicast-oscoap}}.

OSCOAP builds on CBOR Object Signing and Encryption (COSE) {{I-D.ietf-cose-msg}}, providing end-to-end encryption, integrity, replay protection, and secure message binding. The use of OSCOAP is signaled with the CoAP option Object-Security, defined in {{option}}. OSCOAP provides protection of CoAP payload, certain options, and header fields. The solution transforms an unprotected CoAP message into a protected CoAP message in the following way: the unprotected CoAP message is protected by including payload (if present), certain options, and header fields in a COSE object. The message fields that have been encrypted are removed from the message whereas the Object-Security option and the COSE object are added, see {{fig-sketch}}.

~~~~~~~~~~~
Client                                           Server
   |  request:                                     |
   |    GET example.com                            |
   |    [Header, Token, Options:{...,              |
   |     Object-Security:COSE object}]             |
   +---------------------------------------------->|
   |  response:                                    |
   |    2.05 (Content)                             |
   |    [Header, Token, Options:{...,              |
   |     Object-Security:-}, Payload:COSE object]  |
   |<----------------------------------------------+
   |                                               |
~~~~~~~~~~~
{: #fig-sketch title="Sketch of OSCOAP" artwork-align="center"}

OSCOAP may be used in extremely constrained settings, where CoAP over DTLS may be prohibitive e.g. due to large code size. Alternatively, OSCOAP can be combined with DTLS, thereby enabling end-to-end security of e.g. CoAP payload and options, in combination with hop-by-hop protection of the entire CoAP message, during transport between end-point and intermediary node. Examples of the use of OSCOAP are given in {{examples}}.

The message protection provided by OSCOAP can alternatively be applied only to the payload of individual messages. We call this object security of content (OSCON) and it is defined in {{oscon}}.

## Terminology {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}. These words may also appear in this document in lowercase, absent their normative meanings.

Readers are expected to be familiar with the terms and concepts described in CoAP {{RFC7252}}, Observe {{RFC7641}}, Blockwise {{RFC7959}}, COSE {{I-D.ietf-cose-msg}}, CBOR {{RFC7049}}, CDDL {{I-D.greevenbosch-appsawg-cbor-cddl}}, and constrained environments {{RFC7228}}.

# The Object-Security Option {#option}

The Object-Security option (see {{fig-option}}) indicates that OSCOAP is used to protect the CoAP message exchange. The Object-Security option is critical, safe to forward, part of the cache key, not repeatable, and opaque.

~~~~~~~~~~~
+-----+---+---+---+---+-----------------+--------+--------+
| No. | C | U | N | R | Name            | Format | Length |
+-----+---+---+---+---+-----------------+--------+--------|
| TBD | x |   |   |   | Object-Security | opaque | 0-     |
+-----+---+---+---+---+-----------------+--------+--------+
     C=Critical, U=Unsafe, N=NoCacheKey, R=Repeatable
~~~~~~~~~~~
{: #fig-option title="The Object-Security Option" artwork-align="center"}

A successful response to a request with the Object-Security option SHALL contain the Object-Security option. A CoAP proxy SHOULD NOT cache a response to a request with an Object-Security option, since the response is only applicable to the original client's request. The Object-Security option is included in the cache key for backward compatibility with proxies not recognizing the Object-Security option. The effect is that messages with the Object-Security option will never generate cache hits. For Max-Age processing, see {{max-age}}. 

The protection is achieved by means of a COSE object (see {{cose-object}}) included in the protected CoAP message. The placement of the COSE object depends on whether the method/response code allows payload (see {{RFC7252}}):

* If the method/response code allows payload, then the COSE object is the payload of the protected message, and the Object-Security option has length zero. An endpoint receiving a CoAP message with payload, that also contains a non-empty Object-Security option SHALL treat it as malformed and reject it.

* If the method/response code does not allow payload, then the COSE object is the value of the Object-Security option and the length of the Object-Security option is equal to the size of the COSE object. An endpoint receiving a CoAP message without payload, that also contains an empty Object-Security option SHALL treat it as malformed and reject it.

The size of the COSE object depends on whether the method/response code allows payload, if the message is a request or response, on the set of options that are included in the unprotected message, the AEAD algorithm, the length of the information identifying the security context, and the length of the sequence number.

# The Security Context {#context}

OSCOAP uses COSE with an Authenticated Encryption with Additional Data (AEAD) algorithm between a CoAP client and a CoAP server. An implementation supporting this specification MAY only implement the client part or MAY only the server part.

The specification requires that client and server establish a security context to apply to the COSE objects protecting the CoAP messages. In this section we define the security context, and also specify how to derive the initial security contexts in client and server based on common shared secret and a key derivation function (KDF).

## Security Context Definition {#context-definition}

The security context is the set of information elements necessary to carry out the cryptographic operations in OSCOAP. For each endpoint, the security context is composed of a "Common Context", a "Sender Context", and a "Recipient Context".

The endpoints protect messages to send using the Sender Context and verify messages received using the Recipient Context, both contexts being derived from the Common Context and other data.


Each (Sender Context, Recipient Context)-pair has a unique ID. An endpoint uses its Sender ID (SID) to derive its Sender Context, and the other endpoint uses the same ID, now called Recipient ID (RID), to derive its Recipient Context. In communication between two endpoints, the Sender Context of one endpoint matches the Recipient Context of the other endpoint, and vice versa. Thus the two security contexts identified by the same IDs in the two endpoints are not the same, but they are partly mirrored.  Retrieval and use of the security context are shown in {{fig-context}}.

~~~~~~~~~~~
               .------------.           .------------.
               |  Common,   |           |  Common,   |
               |  Sender,   |           |  Recipient,|
               |  Recipient |           |  Sender    |
               '------------'           '------------'
                   Client                   Server
                      |                       |
Retrieve context for  | request:              |
 target resource      | [Token = Token1,      |
Protect request with  |  kid = SID, ...]      |
  Sender Context      +---------------------->| Retrieve context with
                      |                       |  RID = SID
                      |                       | Verify request with
                      |                       |  Recipient Context
                      | response:             | Protect response with
                      | [Token = Token1, ...] |  Sender Context
Retrieve context with |<----------------------+
 Token = Token1       |                       |
Verify request with   |                       |
 Recipient Context    |                       |
~~~~~~~~~~~
{: #fig-context title="Retrieval and use of the Security Context" artwork-align="center"}

The Common Context contains the following parameters:

* Algorithm (Alg). Value that identifies the COSE AEAD algorithm to use for encryption. Its value is immutable once the security context is established.

* Master Secret. Variable length, uniformly random byte string containing the key used to derive traffic keys and IVs. Its value is immutable once the security context is established.

* Master Salt (OPTIONAL). Variable length byte string containing the salt used to derive traffic keys and IVs. Its value is immutable once the security context is established.

The Sender Context contains the following parameters:

* Sender ID. Variable length byte string identifying the Sender Context. Its value is immutable once the security context is established.

* Sender Key. Byte string containing the symmetric key to protect messages to send. Derived from Common Context and Sender ID. Length is determined by Algorithm. Its value is immutable once the security context is established.

* Sender IV. Byte string containing the IV to protect messages to send. Derived from Common Context and Sender ID. Length is determined by Algorithm. Its value is immutable once the security context is established.

* Sequence Number. Non-negative integer used to protect requests and observe responses to send. Used as partial IV {{I-D.ietf-cose-msg}} to generate unique nonces for the AEAD. Maximum value is determined by Algorithm.

The Recipient Context contains the following parameters:

* Recipient ID. Variable length byte string identifying the Recipient Context. Its value is immutable once the security context is established.

* Recipient Key. Byte string containing the symmetric key to verify messages received. Derived from Common Context and Recipient ID. Length is determined by the Algorithm. Its value is immutable once the security context is established.

* Recipient IV. Byte string containing the IV to verify messages received. Derived from Common Context and Recipient ID. Length is determined by Algorithm. Its value is immutable once the security context is established.

* Replay Window. The replay window to verify requests and observe responses received.

An endpoint may free up memory by not storing the Sender Key, Sender IV, Recipient Key, and Recipient IV, deriving them from the Common Context when needed. Alternatively, an endpoint may free up memory by not storing the Master Secret and Master Salt after the other parameters have been derived.

The endpoints MAY interchange the client and server roles while maintaining the same security context. When this happens, the former server still protects messages to send using its Sender Context, and verifies messages received using its Recipient Context. The same is also true for the former client. The endpoints MUST NOT change the Sender/Recipient ID. In other words, changing the roles does not change the set of keys to be used.

## Derivation of Security Context Parameters {#context-derivation}

The parameters in the security context are derived from a small set of input parameters. The following input parameters SHALL be pre-established:

* Master Secret

* Sender ID

* Recipient ID

The following input parameters MAY be pre-established. In case any of these parameters is not pre-established, the default value indicated below is used:

* AEAD Algorithm (Alg)

   - Default is AES-CCM-64-64-128 (value 12)

* Master Salt

   - Default is the empty string

* Key Derivation Function (KDF)

   - Default is HKDF SHA-256

* Replay Window Type and Size

   - Default is DTLS-type replay window with size 64

How the input parameters are pre-established, is application specific. The EDHOC protocol [I-D.selander-ace-cose-ecdhe] enables the establishment of input parameters with the property of forward secrecy and negotiation of KDF and AEAD, it thus provides all necessary pre-requisite steps for using OSCOAP as defined here.

### Derivation of Sender Key/IV, Recipient Key/IV 

The KDF MUST be one of the HKDF {{RFC5869}} algorithms defined in COSE. HKDF SHA-256 is mandatory to implement. The security context parameters Sender Key/IV and Recipient Key/IV SHALL be derived from the input parameters using the HKDF, which consists of the composition of the HKDF-Extract and HKDF-Expand steps ({{RFC5869}}):

~~~~~~~~~~~
   output parameter = HKDF(salt, IKM, info, L) 
~~~~~~~~~~~

where:

* salt is the Master Salt as defined above
* IKM is the Master Secret is defined above
* info is a serialized CBOR array consisting of:

~~~~~~~~~~~ CDDL
   info = [
       id : bstr,
       alg : int,
       type : tstr,
       L : bstr
   ]
~~~~~~~~~~~
~~~~~~~~~~~
   * id is the Sender ID or Recipient ID

   * type is "Key" or "IV"
~~~~~~~~~~~

* L is the key/IV size of the AEAD algorithm in octets without leading zeroes.

For example, if the algorithm AES-CCM-64-64-128 (see Section 10.2 in {{I-D.ietf-cose-msg}}) is used, L is 16 bytes for keys and 7 bytes for IVs.

### Initial Sequence Numbers and Replay Window

The Sequence Number is initialized to 0. The supported types of replay protection and replay window length is application specific and depends on the lower layers. It is mandatory to support a DTLS-type replay window with size 64. This default Replay Window is initiated as described in Section 4.1.2.6 of {{RFC6347}}. 

## Requirements on the Security Context Parameters {#context-requirements}

As collisions may lead to the loss of both confidentiality and integrity, Sender ID SHALL be unique in the set of all security contexts using the same Master Secret. Normally (e.g. when using EDHOC) Sender IDs can be very short. Note that Sender IDs of different lengths can be used with the same Master Secret. E.g. the SID with value 0x00 is different from the SID with the value 0x0000. If Sender ID uniqueness cannot be guaranteed, random Sender IDs MUST be used. Random Sender IDs MUST be long enough so that the probability of collisions is negligible.

To enable retrieval of the right Recipient Context, the Recipient ID SHOULD be unique in the sets of all Recipient Contexts used by an endpoint.

The same Master Salt MAY be used with several Master Secrets.

# URI Schemes and Protected Resources {#resources}

The use of OSCOAP does not affect the URI scheme and OSCOAP can therefore be used with any URI scheme defined for CoAP. The set of resources and methods that requires OSCOAP is decided by the application. The set of resources and methods that can be used with a certain security context is decided by the application. For each resource and method, clients need to be able to retrieve the correct security context to use. For each resource and method, servers need to be able to determine whether the security context is authorized. A server receiving an unprotected request to a resource and method requiring OSCOAP SHALL reject the message with error code 4.01 (Unauthorized). A server receiving a protected request with a security context not authorized for use with the resource and method SHALL reject the message with error code 4.01 (Unauthorized).

# Protected CoAP Message Fields {#coap-headers-and-options} 

OSCOAP transforms an unprotected CoAP message into a protected CoAP message, and vice versa. This section defines how the unprotected CoAP message fields are protected. OSCOAP protects as much of the unprotected CoAP message as possible, while still allowing forward proxy operations {{I-D.hartke-core-e2e-security-reqs}}. 

This section also outlines how the message fields are processed and transferred, a detailed description is provided in {{processing}}. Message fields of the unprotected CoAP message are either transferred in the header/options part of the protected CoAP message, or in the plaintext of the COSE object. Depending on which, the location of the message field in the protected CoAP message is called "outer" or "inner": 

* Inner message field = message field included in the plaintext of the COSE object of the protected CoAP message (see {{plaintext}})
* Outer message field = message field included in the header or options part of the protected CoAP message

The inner message fields are by definition encrypted and integrity protected by the COSE object. The outer message fields are not encrypted and thus visible to a proxy, but may be integrity protected by including the message field values in the AAD of the COSE object (see {{AAD}}).

Note that, even though the message formats are slightly different, OSCOAP complies with CoAP over unreliable transport {{RFC7252}} as well as CoAP over reliable transport {{I-D.ietf-core-coap-tcp-tls}}.

## CoAP Payload {#coap-payload}

The CoAP Payload SHALL be encrypted and integrity protected, and thus is an inner message field.

The sending endpoint writes the payload of the unprotected CoAP message into the plaintext of the COSE object (see {{protected-coap-formatting-req}} and {{protected-coap-formatting-resp}}). 

The receiving endpoint verifies and decrypts the COSE object, and recreates the payload of the unprotected CoAP message (see {{verif-coap-req}} and {{verif-coap-resp}}).

## CoAP Header {#coap-header}

Many CoAP header fields are required to be read and changed during a normal message exchange or when traversing a proxy and thus cannot be protected between the endpoints, e.g. CoAP message layer fields such as Message ID.

The CoAP header field Code MUST be sent in plaintext to support RESTful processing, but MUST be integrity protected to prevent an intermediary from changing, e.g. from GET to DELETE.  The CoAP version number MUST be integrity protected to prevent potential future version-based attacks. Note that while the version number is not sent in each CoAP message over reliable transport {{I-D.ietf-core-coap-tcp-tls}}, its value is known to client and server.

Other CoAP header fields SHALL neither be integrity protected nor encrypted. The CoAP header fields are thus outer message fields.

The sending endpoint SHALL copy the header fields from the unprotected CoAP message to the protected CoAP message. The receiving endpoint SHALL copy the header fields from the protected CoAP message to the unprotected CoAP message. Both sender and receiver inserts the CoAP version number and header field Code in the AAD of the COSE object (see section {{AAD}}). 


## CoAP Options {#coap-options}

Most options are encrypted and integrity protected, and thus inner message fields. But to allow certain proxy operations, some options have outer values and are neither encrypted nor integrity protected, while others require special processing. Indeed, certain options may have both an inner value and a potentially different outer value, where the inner value is intended for the destination endpoint and the outer value is intended for the proxy. 

~~~~~~~~~~~
+----+---+---+---+---+----------------+--------+--------+---+---+
| No.| C | U | N | R | Name           | Format | Length | E | U |
+----+---+---+---+---+----------------+--------+--------+---+---+
|  1 | x |   |   | x | If-Match       | opaque | 0-8    | x |   |
|  3 | x | x | - |   | Uri-Host       | string | 1-255  |   | x |
|  4 |   |   |   | x | ETag           | opaque | 1-8    | x |   |
|  5 | x |   |   |   | If-None-Match  | empty  | 0      | x |   |
|  6 |   | x | - |   | Observe        | uint   | 0-3    |   | * |
|  7 | x | x | - |   | Uri-Port       | uint   | 0-2    |   | x |
|  8 |   |   |   | x | Location-Path  | string | 0-255  | x |   |
| 11 | x | x | - | x | Uri-Path       | string | 0-255  | x |   |
| 12 |   |   |   |   | Content-Format | uint   | 0-2    | x |   |
| 14 |   | x | - |   | Max-Age        | uint   | 0-4    | * |   |
| 15 | x | x | - | x | Uri-Query      | string | 0-255  | x |   |
| 17 | x |   |   |   | Accept         | uint   | 0-2    | x |   |
| 20 |   |   |   | x | Location-Query | string | 0-255  | x |   |
| 23 | x | x | - | - | Block2         | uint   | 0-3    | * |   |
| 27 | x | x | - | - | Block1         | uint   | 0-3    | * |   |
| 28 |   |   | x |   | Size2          | unit   | 0-4    | * |   |
| 35 | x | x | - |   | Proxy-Uri      | string | 1-1034 |   | * |
| 39 | x | x | - |   | Proxy-Scheme   | string | 1-255  |   | x |
| 60 |   |   | x |   | Size1          | uint   | 0-4    | * |   |
+----+---+---+---+---+----------------+--------+--------+---+---+
      C=Critical, U=Unsafe, N=NoCacheKey, R=Repeatable,
  E=Encrypt and Integrity Protect, U=Unprotected, *=Special
~~~~~~~~~~~
{: #protected-coap-options title="Protection of CoAP Options" artwork-align="center"}


A summary of how options are protected and processed is shown in {{protected-coap-options}}. The CoAP options are partitioned into two classes: 

* E - options which are encrypted and integrity protected, and
* U - options which are neither encrypted nor integrity protected.

Options within each class are protected and processed in a similar way, but certain options which require special processing as described in the subsections and indicated by a \'*\' in {{protected-coap-options}}.

Unless specified otherwise, CoAP options not listed in {{protected-coap-options}} SHALL be encrypted and integrity protected and processed as class E options.

Specifications of new CoAP options SHOULD specify how they are processed with OSCOAP. New COAP options SHOULD be of class E and SHOULD NOT have outer options unless a forwarding proxy needs to read an option value. If a certain option is both inner and outer, the two values SHOULD NOT be the same, unless a proxy is required by specification to be able to read the end-to-end value.

### Class E Options {#class-e}

For options in class E (see {{protected-coap-options}}) the option value in the unprotected CoAP message, if present, SHALL be encrypted and integrity protected between the endpoints, and thus is not visible to or possible to change by intermediary nodes.  Hence the actions resulting from the use of such options is analogous to communicating in a protected manner with the endpoint. For example, a client using an ETag option will not be served by a proxy.

The sending endpoint SHALL write the class E option from the unprotected CoAP message into the plaintext of the COSE object (see {{protected-coap-formatting-req}} and {{protected-coap-formatting-resp}}). 

Except for the special options described in the subsections, the sending endpoint SHALL NOT use the outer options of class E. However, note that an intermediary may, legitimately or not, add, change or remove the value of an outer option.

Except for the Block options {{block-options}}, the receiving endpoint SHALL discard any outer options of class E from the protected CoAP message and SHALL replace it with the value from the COSE object when present (see {{verif-coap-req}} and {{verif-coap-resp}}). 


#### Max-Age {#max-age}

An inner Max-Age option is used as defined in {{RFC7252}} taking into account that it is not accessible to proxies.

Since OSCOAP binds CoAP responses to requests, a cached response would not be possible to use for any other request. To avoid unnecessary caching in proxies not recognizing the Object-Security, a server MAY add an outer Max-Age option with value zero to protected CoAP responses (see Section 5.6.1 of {{RFC7252}}). 

The outer Max-Age option is not integrity protected.


#### The Block Options {#block-options}

TODO: Update processing to support multiple concurrently proceeding requests

Blockwise {{RFC7959}} is an optional feature. An implementation MAY support RFC7252 with the Object-Security option without supporting {{RFC7959}}.

The Block options (Block1, Block2, Size1 and Size2) MAY be either only inner options, only outer options or both inner and outer options. The inner and outer options are processed independently.  

The inner block options are used for endpoint-to-endpoint secure fragmentation of payload into blocks and protection of information about the fragmentation (block number, last block, etc.). Additionally, a proxy may arbitrarily do fragmentation operations on the protected CoAP message, adding outer block options that are not intended to be verified by any endpoint or proxy.  

There SHALL be a security policy defining a maximum unfragmented message size for inner Block options such that messages exceeding this size SHALL be fragmented by the sending endpoint. 

In addition to the processing defined for the inner Block options inherent to class E options, the AEAD Tag from each block SHALL be included in the calculation of the Tag for the next block (see {{AAD}}), so that each block in the order being sent can be verified as it arrives. 

The protected CoAP message may be fragmented by the sending endpoint or proxy as defined in {{RFC7959}}, in which case the outer Block options are being used. The outer Block options SHALL neither be encrypted nor integrity protected. 

An endpoint receiving a message with an outer Block option SHALL first process this option according to {{RFC7959}}, until all blocks of the protected CoAP message has been received, or the cumulated message size of the exceeds the maximum unfragmented message size. In the latter case the message SHALL be discarded. In the former case, the processing of the protected CoAP message continues as defined in this document (see {{verif-coap-req}} and {{verif-coap-resp}}). 

If the unprotected CoAP message contains Block options, the receiving endpoint processes this according to {{RFC7959}}.


### Class U Options {#class-u}

Options in this class are used to support forward proxy operations. Unless otherwise specified, the sending endpoint  SHALL copy a Class U option from the unprotected CoAP message to the protected CoAP message, and v.v. for the receiving endpoint. 

#### Observe {#observe}

Observe {{RFC7641}} is an optional feature. An implementation MAY support RFC7252 with the Object-Security option without supporting {{RFC7641}}. The Observe option as used here targets the requirements on forwarding of {{I-D.hartke-core-e2e-security-reqs}} (Section 2.2.1.2).

To secure the order of the notifications, the Partial IV of the response is used instead of the Observe option for the responses, which may be changed by a proxy. However, in order for a proxy to support forwarding of notifications, there must be an outer Observe option.

The OSCOAP client SHALL copy Observe from the unprotected CoAP request to the protected CoAP request, and SHALL also include Observe as an inner option. The OSCOAP server SHALL discard the outer Observe option of the protected CoAP request and SHALL replace it with the value from the COSE object.

The OSCOAP server SHALL copy Observe from the unprotected CoAP response to the protected CoAP response. The OSCOAP client implementation SHALL discard the Observe option of the protected response and SHALL set the value of the Observe option of the unprotected response to the last 3 bytes of the Partial IV of the response.
 
The outer Observe option is not integrity protected, but the order of the notifications is preserved. 


#### Uri-Host, Uri-Port, and Proxy-Scheme 

The sending endpoint SHALL copy Uri-Host, Uri-Port, and Proxy-Scheme from the unprotected CoAP message to the protected CoAP message. When Uri-Host, Uri-Port, Proxy-Scheme options are present, Proxy-Uri is not used {{RFC7252}}. 


#### Proxy-Uri {#proxy-uri}

Proxy-Uri, when present, is split by OSCOAP into class U options and privacy sensitive class E options, which are processed accordingly. When Proxy-Uri is used in the unprotected CoAP message, Uri-* are not present {{RFC7252}}.

The sending endpoint SHALL first decompose the Proxy-Uri value of the unprotected CoAP message into the Proxy-Scheme, Uri-Host, Uri-Port, Uri-Path and Uri-Query options (if present) according to section 6.4 of {{RFC7252}}. 

Uri-Path and Uri-Query are class E options and MUST be protected and processed as if obtained from the unprotected CoAP message, see {{class-e}}. 

The value of the Proxy-Uri option of the protected CoAP message MUST be replaced with Proxy-Scheme, Uri-Host, Uri-Port options (if present) composed according to section 6.5 of {{RFC7252}} and MUST be processed as a class U option, see {{class-u}}.

# The COSE Object {#cose-object}

This section defines how to use COSE {{I-D.ietf-cose-msg}} to wrap and protect data in the unprotected CoAP message. OSCOAP uses the untagged COSE\_Encrypt0 structure with an Authenticated Encryption with Additional Data (AEAD) algorithm. The key lengths, IV lengths, and maximum sequence number are algorithm dependent.
 
The AEAD algorithm AES-CCM-64-64-128 defined in Section 10.2 of {{I-D.ietf-cose-msg}} is mandatory to implement. For AES-CCM-64-64-128 the length of Sender Key and Recipient Key is 128 bits, the length of nonce, Sender IV, and Recipient IV is 7 bytes, and the maximum Sequence Number is 2^55 - 1.

The nonce is constructed as described in Section 3.1 of {{I-D.ietf-cose-msg}}, i.e. by padding the partial IV (Sequence Number in network byte order) with zeroes and XORing it with the context IV (Sender IV or Recipient IV). The first bit in the Sender IV or Recipient IV SHALL be flipped in responses.

We denote by Plaintext the data that is encrypted and integrity protected, and by Additional Authenticated Data (AAD) the data that is integrity protected only.

The COSE Object SHALL be a COSE_Encrypt0 object with fields defined as follows

- The "protected" field includes:

   * The "Partial IV" parameter. The value is set to the Sender Sequence Number. The Partial IV SHALL be of minimum length needed to encode the sequence number. This parameter SHALL be present in requests, and MAY be present in responses.

   * The "kid" parameter. The value is set to the Sender ID (see {{context}}). This parameter SHALL be present in requests.

- The "unprotected" field is empty.

-  The "ciphertext" field is computed from the Plaintext (see {{plaintext}}) and the Additional Authenticated Data (AAD) (see {{AAD}}) following Section 5.2 of {{I-D.ietf-cose-msg}}.

The encryption process is described in Section 5.3 of {{I-D.ietf-cose-msg}}.

## Plaintext {#plaintext}

The Plaintext is formatted as a CoAP message without Header (see {{fig-plaintext}}) consisting of:

- all CoAP Options present in the unprotected message that are encrypted (see {{coap-headers-and-options}}). The options are encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included encrypted option); and

- the Payload of unprotected CoAP message, if present, and in that case prefixed by the one-byte Payload Marker (0xFF).

~~~~~~~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Options to Encrypt (if any) ...                             
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
   ver : uint,
   code : uint,
   alg : int,
   request_id : bstr,
   request_seq : bstr
]
~~~~~~~~~~~

where:

- ver: uint, contains the CoAP version number, as defined in Section 3 of {{RFC7252}}.

- code: uint, contains is the CoAP Code of the unprotected CoAP message, as defined in Section 3 of {{RFC7252}}.

- alg: int, contains the Algorithm from the security context used for the exchange (see {{context-definition}}).

- request_id : bstr, contains the identifier for the endpoint sending the request and verifying the response; which means that for the endpoint sending the response, the id has value Recipient ID, while for the endpoint receiving the response, id has the value Sender ID.

-  request_seq : bstr, contains the value of the "Partial IV" in the COSE object of the request (see Section 5).

# Sequence Numbers, Replay, Message Binding, and Freshness {#sequence-numbers}

An AEAD nonce MUST NOT be used more than once per AEAD key. In order to assure unique nonces, each Sender Context contains a Sender Sequence Number used to protect requests and Observe responses. The maximum sequence number is algorithm dependent and SHALL be 2^(nonce length in bits - 1) - 1. If the Sender Sequence Number exceeds the maximum sequence number, the endpoint MUST NOT process any more messages with the given Sender Context. The endpoint SHOULD acquire a new security context (and consequently inform the other endpoint) before this happens. The latter is out of scope of this memo.

In order to protect from replay of messages, each Recipient Context contains a Replay Window used to verify request and Observe responses. A receiving endpoint SHALL verify that a Sequence Number (Partial IV) received in the COSE object has not been received before in the Recipient Context. The size and type of the Replay Window depends on the use case and lower protocol layers. In case of reliable and ordered transport, the recipient MAY just store the last received sequence number and require that newly received Sequence Numbers equals the last received Sequence Number + 1.

In order to prevent response delay and mismatch attacks {{I-D.mattsson-core-coap-actuators}} from on-path attackers and compromised proxies, OSCOAP binds responses to the request by including the request's ID (Sender ID or Recipient ID) and sequence number in the AAD of the response. The server therefore needs to store the request's ID (Sender ID or Recipient ID) and sequence number until all responses has been sent.

For responses without Observe, OSCOAP provides absolute freshness. For requests, and responses with Observe, OSCOAP provides relative freshness in the sense that the sequence numbers allows a recipient to determine the relative order of messages.  For applications having stronger demands on freshness (e.g. control of actuators), OSCOAP needs to be augmented with mechanisms providing absolute freshness [I-D.mattsson-core-coap-actuators]. 

# Processing {#processing}

TODO: Update include new Observe processing

## Protecting the Request {#protected-coap-formatting-req}

Given an unprotected CoAP request, including header, options and payload, the client SHALL perform the following steps to create a protected CoAP request using a security context associated with the target resource (see {{context}}).

1. Compute the COSE object as specified in {{cose-object}}

    * the AEAD nonce is created by XORing the Sender IV (context IV) with the Sender Sequence Number in network byte order (partial IV).
    
2. Format the protected CoAP message as an ordinary CoAP message, with the following Header, Options, and Payload, based on the unprotected CoAP message:

    * The CoAP header is the same as the unprotected CoAP message.
    
    * If present, the CoAP option Proxy-Uri is decomposed as described in {{proxy-uri}}.

    * The CoAP options which are of class E ({{coap-headers-and-options}}) are removed. The Object-Security option is added.

    * If the message type of the unprotected CoAP message does not allow Payload, then the value of the Object-Security option is the COSE object. If the message type of the unprotected CoAP message allows Payload, then the Object-Security option is empty and the Payload of the protected CoAP message is the COSE object.

4. Store the association Token - Security Context. The Client SHALL be able to find the correct security context used to protect the request and verify the response with use of the Token of the message exchange.

5. Increment the Sender Sequence Number by one.

## Verifying the Request {#verif-coap-req}

A CoAP server receiving a message containing the Object-Security option and a outer Block option SHALL first process this option according to {{RFC7959}}, until all blocks of the protected CoAP message has been received, see {{block-options}}.

A CoAP server receiving a message containing the Object-Security option SHALL perform the following steps, using the Recipient Context identified by the "kid" parameter in the received COSE object:

1. Verify the Sequence Number in the Partial IV parameter, as described in {{sequence-numbers}}. If it cannot be verified that the Sequence Number has not been received before, the server MUST stop processing the request.

2. Recreate the Additional Authenticated Data, as described in {{cose-object}}.

3. Compose the AEAD nonce by XORing the Recipient IV (context IV) with the padded Partial IV parameter, received in the COSE Object. 

4. Retrieve the Recipient Key.

5. Verify and decrypt the message. If the verification fails, the server MUST stop processing the request.

6. If the message verifies, update the Recipient Replay Window, as described in {{sequence-numbers}}.

7. Restore the unprotected request by adding any decrypted options or payload from the plaintext. Any outer E options ({{coap-headers-and-options}}) are overwritten. The Object-Security option is removed.

## Protecting the Response {#protected-coap-formatting-resp}

Given an unprotected CoAP response, including header, options, and payload, the server SHALL perform the following steps to create a protected CoAP response, using the security context identified by the Context Identifier of the received request:

2. Compute the COSE object as specified in Section {{cose-object}}
  * The AEAD nonce is created by XORing the Sender IV (context IV) and the padded Sender Sequence Number.
  
3. Format the protected CoAP message as an ordinary CoAP message, with the following Header, Options, and Payload based on the unprotected CoAP message:
  * The CoAP header is the same as the unprotected CoAP message.
  * The CoAP options which are of class E are removed, except any special option (labelled '*') that is present which has its outer value ({{coap-headers-and-options}}). The Object-Security option is added. 
  * If the message type of the unprotected CoAP message does not allow Payload, then the value of the Object-Security option is the COSE object. If the message type of the unprotected CoAP message allows Payload, then the Object-Security option is empty and the Payload of the protected CoAP message is the COSE object.

4. Increment the Sender Sequence Number by one.


## Verifying the Response {#verif-coap-resp}

A CoAP client receiving a message containing the Object-Security option SHALL perform the following steps, using the security context identified by the Token of the received response:

0. If the message contain an outer Block option the client SHALL process this option according to {{RFC7959}}, until all blocks of the protected CoAP message has been received, see {{block-options}}.

1. Verify the Sequence Number in the Partial IV parameter as described in {{sequence-numbers}}. If it cannot be verified that the Sequence Number has not been received before, the client MUST stop processing the response.

2. Recreate the Additional Authenticated Data as described in {{cose-object}}.

3. Compose the AEAD nonce by XORing the Recipient IV (context IV) with the Partial IV parameter, received in the COSE Object.

4. Retrieve the Recipient Key.

5. Verify and decrypt the message. If the verification fails, the client MUST stop processing the response.

6. If the message verifies, update the Recipient Replay Window, as described in {{sequence-numbers}}.

7. Restore the unprotected response by adding any decrypted options or payload from the plaintext. Any class E options ({{coap-headers-and-options}}) are overwritten. The Object-Security option is removed. 



# Security Considerations {#sec-considerations}

In scenarios with intermediary nodes such as proxies or brokers, transport layer security such as DTLS only protects data hop-by-hop. As a consequence the intermediary nodes can read and modify information. The trust model where all intermediate nodes are considered trustworthy is problematic, not only from a privacy perspective, but also from a security perspective, as the intermediaries are free to delete resources on sensors and falsify commands to actuators (such as "unlock door", "start fire alarm", "raise bridge"). Even in the rare cases, where all the owners of the intermediary nodes are fully trusted, attacks and data breaches make such an architecture brittle.

DTLS protects hop-by-hop the entire CoAP message, including header, options, and payload. OSCOAP protects end-to-end the payload, and all information in the options and header, that is not required for forwarding (see {{coap-headers-and-options}}). DTLS and OSCOAP can be combined, thereby enabling end-to-end security of CoAP payload, in combination with hop-by-hop protection of the entire CoAP message, during transport between end-point and intermediary node.

The CoAP message layer, however, cannot be protected end-to-end through intermediary devices since the parameters Type and Message ID, as well as Token and Token Length may be changed by a proxy. Moreover, messages that are not possible to verify should for security reasons not always be acknowledged but in some cases be silently dropped. This would not comply with CoAP message layer, but does not have an impact on the application layer security solution, since message layer is excluded from that.

The use of COSE to protect CoAP messages as specified in this document requires an established security context. The method to establish the security context described in {{context-derivation}} is based on a common shared secret material and key derivation function in client and server. EDHOC {{I-D.selander-ace-cose-ecdhe}} describes an augmented Diffie-Hellman key exchange to produce forward secret keying material and agree on crypto algorithms necessary for OSCOAP, authenticated with pre-established credentials. These pre-established credentials may, in turn, be provisioned using a trusted third party such as described in the OAuth-based ACE framework {{I-D.ietf-ace-oauth-authz}}. An OSCOAP profile of ACE is described in {{I-D.seitz-ace-oscoap-profile}}.

The mandatory-to-implement AEAD algorithm AES-CCM-64-64-128 is selected for broad applicability in terms of message size (2^64 blocks) and maximum no. messages (2^56-1). Compatibility with CCM* is achieved by using the algorithm AES-CCM-16-64-128 {{I-D.ietf-cose-msg}}.

Most AEAD algorithms require a unique nonce for each message, for which the sequence numbers in the COSE message field "Partial IV" is used. If the recipient accepts any sequence number larger than the one previously received, then the problem of sequence number synchronization is avoided. With reliable transport it may be defined that only messages with sequence number which are equal to previous sequence number + 1 are accepted. The alternatives to sequence numbers have their issues: very constrained devices may not be able to support accurate time, or to generate and store large numbers of random nonces. The requirement to change key at counter wrap is a complication, but it also forces the user of this specification to think about implementing key renewal.

The encrypted block options enable the sender to split large messages into protected blocks such that the receiving node can verify blocks before having received the complete message. In order to protect from attacks replacing blocks from a different message with the same block number between same endpoints and same resource at roughly the same time, the AEAD Tag from the message containing one block is included in the external_aad of the message containing the next block. 

The unencrypted block options allow for arbitrary proxy fragmentation operations that cannot be verified by the endpoints, but can by policy be restricted in size since the encrypted options allow for secure fragmentation of very large messages. A maximum message size (above which the sending endpoint fragments the message and the receiving endpoint discards the message, if complying to the policy) may be obtained as part of normal resource discovery.

Applications need to use a padding scheme if the content of a message can be determined solely from the length of the payload.  As an example, the strings "YES" and "NO" even if encrypted can be distinguished from each other as there is no padding supplied by the current set of encryption algorithms.  Some information can be determined even from looking at boundary conditions.  An example of this would be returning an integer between 0 and 100 where lengths of 1, 2 and 3 will provide information about where in the range things are. Three different methods to deal with this are: 1) ensure that all messages are the same length.  For example using 0 and 1 instead of 'yes' and 'no'.  2) Use a character which is not part of the responses to pad to a fixed length.  For example, pad with a space to three characters.  3) Use the PKCS #7 style padding scheme where m bytes are appended each having the value of m.  For example, appending a 0 to "YES" and two 1's to "NO".  This style of padding means that all values need to be padded.

# Privacy Considerations

Privacy threats executed through intermediate nodes are considerably reduced by means of OSCOAP. End-to-end integrity protection and encryption of CoAP payload and all options that are not used for forwarding, provide mitigation against attacks on sensor and actuator communication, which may have a direct impact on the personal sphere.

CoAP headers sent in plaintext allow for example matching of CON and ACK (CoAP Message Identifier), matching of request and responses (Token) and traffic analysis.





# IANA Considerations {#iana}

Note to RFC Editor: Please replace all occurrences of "\[\[this document\]\]" with the RFC number of this specification.

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


## Media Type Registrations

The "application/oscon" media type is added to the Media Types registry:

        Type name: application

        Subtype name: oscon

        Required parameters: N/A

        Optional parameters: N/A

        Encoding considerations: binary

        Security considerations: See Appendix C of this document.

        Interoperability considerations: N/A

        Published specification: [[this document]] (this document)

        Applications that use this media type: To be identified

        Fragment identifier considerations: N/A

        Additional information:

        * Magic number(s): N/A

        * File extension(s): N/A

        * Macintosh file type code(s): N/A

        Person & email address to contact for further information:
           Göran Selander <goran.selander@ericsson.com>

        Intended usage: COMMON

        Restrictions on usage: N/A

        Author: Göran Selander, goran.selander@ericsson.com


## CoAP Content Format Registration

The "application/oscon" content format is added to the CoAP Content Format registry:

~~~~~~~~~~~
+-------------------+----------+----+-------------------+
| Media type        | Encoding | ID | Reference         |
+-------------------+----------+----+-------------------+
| application/oscon | -        | 70 | [[this document]] |
+-------------------+----------+----+-------------------+
~~~~~~~~~~~
{: artwork-align="center"}

# Acknowledgments

The following individuals provided input to this document: Christian Amsüss, Carsten Bormann, Joakim Brorsson, Martin Gunnarsson, Klaus Hartke, Jim Schaad, Marco Tiloca, and Malisa Vucinic.

Ludwig Seitz and Goeran Selander worked on this document as part of the CelticPlus project CyberWI, with funding from Vinnova.

--- back

# Test Vectors {#app-vectors}

TODO: This section needs to be updated.

# Examples {#examples}

TODO: This section needs to be updated.

This section gives examples of OSCOAP. The message exchanges are made, based on the assumption that there is a security context established between client and server. For simplicity, these examples only indicate the content of the messages without going into detail of the COSE message format. 

## Secure Access to Sensor

Here is an example targeting the scenario in the Section 2.2.1. - Forwarding of {{I-D.hartke-core-e2e-security-reqs}}. The example illustrates a client requesting the alarm status from a server. In the request, CoAP option Uri-Path is encrypted and integrity protected, and the CoAP header fields Code and Version are integrity protected (see {{coap-headers-and-options}}). In the response, the CoAP Payload is encrypted and integrity protected, and the CoAP header fields Code and Version are integrity protected.

~~~~~~~~~~~
Client  Proxy  Server
   |      |      |
   +----->|      |            Code: 0.01 (GET)
   | GET  |      |           Token: 0x8c
   |      |      | Object-Security: [cid:5fdc, seq:42,
   |      |      |                   {Uri-Path:"alarm_status"},
   |      |      |                   <Tag>]
   |      |      |         Payload: -
   |      |      |
   |      +----->|            Code: 0.01 (GET)
   |      | GET  |           Token: 0x7b
   |      |      | Object-Security: [cid:5fdc, seq:42,
   |      |      |                   {Uri-Path:"alarm_status"},
   |      |      |                   <Tag>]
   |      |      |         Payload: -
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0x7b
   |      |      |         Max-Age: 0
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:56, {"OFF"}, <Tag>]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x8c
   |      |      |         Max-Age: 0
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:56, {"OFF"}, <Tag>]
   |      |      |
~~~~~~~~~~~
{: #get-protected-sig title="Indication of CoAP GET protected with OSCOAP. The brackets [ ... ] indicate a COSE object. The brackets { ... \} indicate encrypted data." } 
{: artwork-align="center"}

Since the unprotected request message (GET) doesn't allow payload, the Object-Security option carries the COSE object as its value.
Since the unprotected response message (Content) allows payload ("OFF"), the COSE object (indicated with \[ ... \]) is carried as the CoAP payload.

The COSE header of the request contains a Context Identifier (cid:5fdc), indicating which security context was used to protect the message and a Sequence Number (seq:42).

The option Uri-Path (alarm_status) and payload ("OFF") are formatted as indicated in {{cose-object}}, and encrypted in the COSE Cipher Text (indicated with \{ ... \}).

The server verifies that the Sequence Number has not been received before (see {{sequence-numbers}}). The client verifies that the Sequence Number has not been received before and that the response message is generated as a response to the sent request message (see {{sequence-numbers}}).

## Secure Subscribe to Sensor

Here is an example targeting the scenario in the Forwarding with observe case  of {{I-D.hartke-core-e2e-security-reqs}}. The example illustrates a client requesting subscription to a blood sugar measurement resource (GET /glucose), and first receiving the value 220 mg/dl, and then a second reading with value 180 mg/dl. The CoAP options Observe, Uri-Path, Content-Format, and Payload are encrypted and integrity protected, and the CoAP header field Code is integrity protected (see {{coap-headers-and-options}}).

~~~~~~~~~~~
Client  Proxy  Server
   |      |      |
   +----->|      |            Code: 0.01 (GET)
   | GET  |      |           Token: 0x83
   |      |      |         Observe: 0
   |      |      | Object-Security: [cid:ca, seq:15b7, {Observe:0,
   |      |      |                   Uri-Path:"glucose"}, <Tag>]
   |      |      |         Payload: -
   |      |      |
   |      +----->|            Code: 0.01 (GET)
   |      | GET  |           Token: 0xbe
   |      |      |         Observe: 0
   |      |      | Object-Security: [cid:ca, seq:15b7, {Observe:0,
   |      |      |                   Uri-Path:"glucose"}, <Tag>]
   |      |      |         Payload: -
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0xbe
   |      |      |         Max-Age: 0
   |      |      |         Observe: 1
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:32c2, {Observe:1, 
   |      |      |                   Content-Format:0, "220"}, <Tag>]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x83
   |      |      |         Max-Age: 0
   |      |      |         Observe: 1
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:32c2, {Observe:1,
   |      |      |                   Content-Format:0, "220"}, <Tag>]
  ...    ...    ...
   |      |      |
   |      |<-----+            Code: 2.05 (Content)
   |      | 2.05 |           Token: 0xbe
   |      |      |         Max-Age: 0
   |      |      |         Observe: 2
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:32c6, {Observe:2, 
   |      |      |                   Content-Format:0, "180"}, <Tag>]
   |      |      |
   |<-----+      |            Code: 2.05 (Content)
   | 2.05 |      |           Token: 0x83
   |      |      |         Max-Age: 0
   |      |      |         Observe: 2
   |      |      | Object-Security: -
   |      |      |         Payload: [seq:32c6, {Observe:2,
   |      |      |                   Content-Format:0, "180"}, <Tag>]
   |      |      |
~~~~~~~~~~~
{: #get-protected-enc title="Indication of CoAP GET protected with OSCOAP. The brackets [ ... ] indicates COSE object. The bracket { ... \} indicates encrypted data." } 
{: artwork-align="center"}

Since the unprotected request message (GET) doesn't allow payload, the COSE object (indicated with \[ ... \]) is carried in the Object-Security option value. Since the unprotected response message (Content) allows payload, the Object-Security option is empty, and the COSE object is carried as the payload.

The COSE header of the request contains a Context Identifier (cid:ca), indicating which security context was used to protect the message and a Sequence Number (seq:15b7).

The options Observe, Content-Format and the payload are formatted as indicated in {{cose-object}}, and encrypted in the COSE ciphertext (indicated with \{ ... \}). 

The server verifies that the Sequence Number has not been received before (see {{sequence-numbers}}). The client verifies that the Sequence Number has not been received before and that the response message is generated as a response to the subscribe request.



# Object Security of Content (OSCON) {#oscon}

TODO: This section needs to be updated.

OSCOAP protects message exchanges end-to-end between a certain client and a
certain server, targeting the security requirements for forward proxy of {{I-D.hartke-core-e2e-security-reqs}}. In contrast, many use cases require one and
the same message to be protected for, and verified by, multiple endpoints, see
caching proxy section of {{I-D.hartke-core-e2e-security-reqs}}. Those security requirements can be addressed by protecting essentially the payload/content of individual messages using the COSE format ({{I-D.ietf-cose-msg}}), rather than the entire request/response message exchange. This is referred to as Object Security of Content (OSCON). 

OSCON transforms an unprotected CoAP message into a protected CoAP message in
the following way: the payload of the unprotected CoAP message is wrapped by
a COSE object, which replaces the payload of the unprotected CoAP message. We
call the result the "protected" CoAP message.

The unprotected payload shall be the plaintext/payload of the COSE object. 
The 'protected' field of the COSE object 'Headers' shall include the context identifier, both for requests and responses.
If the unprotected CoAP message includes a Content-Format option, then the COSE
object shall include a protected 'content type' field, whose value is set to the unprotected message Content-Format value. The Content-Format option of the
protected CoAP message shall be replaced with "application/oscon" ({{iana}})

The COSE object shall be protected (encrypted) and verified (decrypted) as
described in ({{I-D.ietf-cose-msg}}). 

Most AEAD algorithms require a unique nonce for each message. Sequence numbers for partial IV as specified for OSCOAP may be used for replay protection as described in {{sequence-numbers}}. The use of time stamps in the COSE header parameter 'operation time' {{I-D.ietf-cose-msg}} for freshness may be used.

OSCON shall not be used in cases where CoAP header fields (such as Code or
Version) or CoAP options need to be integrity protected or encrypted. OSCON shall not be used in cases which require a secure binding between request and
response.

The scenarios in Sections 3.3 - 3.5 of {{I-D.hartke-core-e2e-security-reqs}} assume multiple recipients for a particular content. In this case the use of symmetric keys does not provide data origin authentication. Therefore the COSE object should in general be protected with a digital signature.

## Overhead OSCON {#appendix-c}

In general there are four different kinds of modes that need to be supported: message authentication code, digital signature, authenticated encryption, and symmetric encryption + digital signature. The use of digital signature is necessary for applications with many legitimate recipients of a given message, and where data origin authentication is required.

To distinguish between these different cases, the tagged structures of 
COSE are used (see Section 2 of {{I-D.ietf-cose-msg}}).

The sizes of COSE messages for selected algorithms are detailed in this section.

The size of the header is shown separately from the size of the MAC/signature.
A 4-byte Context Identifier and a 1-byte Sequence Number are used throughout
all examples, with these values:

* Cid: 0xa1534e3c
* Seq: 0xa3

For each scheme, we indicate the fixed length of these two parameters ("Cid+Seq" column) and of the Tag ("MAC"/"SIG"/"TAG"). The "Message OH" column
shows the total expansions of the CoAP message size, while the "COSE OH" column is calculated from the previous columns.

Overhead incurring from CBOR encoding is also included in the COSE overhead count. 

To make it easier to read, COSE objects are represented using CBOR's diagnostic notation rather than a binary dump.

## MAC Only ## {#ssm-mac}

This example is based on HMAC-SHA256, with truncation to 8 bytes (HMAC 256/64).

Since the key is implicitly known by the recipient, the COSE_Mac0_Tagged structure is used (Section 6.2 of {{I-D.ietf-cose-msg}}).

The object in COSE encoding gives:

~~~~~~~~~~~
996(                         # COSE_Mac0_Tagged
  [
    h'a20444a1534e3c0641a3', # protected:
                               {04:h'a1534e3c',
                                06:h'a3'}
    {},                      # unprotected
    h'',                     # payload
    MAC                      # truncated 8-byte MAC
  ]
)
~~~~~~~~~~~
{: artwork-align="center"}

This COSE object encodes to a total size of 26 bytes.

{{comp-hmac-sha256}} summarizes these results.

~~~~~~~~~~~
+------------------+-----+-----+---------+------------+
|     Structure    | Tid | MAC | COSE OH | Message OH |
+------------------+-----+-----+---------+------------+
| COSE_Mac0_Tagged | 5 B | 8 B |   13 B  |    26 B    |
+------------------+-----+-----+---------+------------+
~~~~~~~~~~~
{: #comp-hmac-sha256 title="Message overhead for a 5-byte Tid using HMAC 256/64"}
{: artwork-align="center"}

## Signature Only {#ssm-dig-sig}

This example is based on ECDSA, with a signature of 64 bytes.

Since only one signature is used, the COSE_Sign1_Tagged structure is used 
(Section 4.2 of {{I-D.ietf-cose-msg}}).

The object in COSE encoding gives:

~~~~~~~~~~~
997(                         # COSE_Sign1_Tagged
  [
    h'a20444a1534e3c0641a3', # protected:
                               {04:h'a1534e3c',
                                06:h'a3'}
    {},                      # unprotected
    h'',                     # payload
    SIG                      # 64-byte signature
  ]
)
~~~~~~~~~~~
{: artwork-align="center"}

This COSE object encodes to a total size of 83 bytes.

{{comp-ecdsa}} summarizes these results.

~~~~~~~~~~~
+-------------------+-----+------+---------+------------+
|     Structure     | Tid |  SIG | COSE OH | Message OH |
+-------------------+-----+------+---------+------------+
| COSE_Sign1_Tagged | 5 B | 64 B |   14 B  |  83 bytes  |
+-------------------+-----+------+---------+------------+
~~~~~~~~~~~
{: #comp-ecdsa title="Message overhead for a 5-byte Tid using 64 byte ECDSA signature."}
{: artwork-align="center"}

## Authenticated Encryption with Additional Data (AEAD) {#sem-auth-enc}

This example is based on AES-CCM with the Tag truncated to 8 bytes. 

Since the key is implicitly known by the recipient, the COSE_Encrypt0_Tagged structure is used (Section 5.2 of {{I-D.ietf-cose-msg}}).

The object in COSE encoding gives:

~~~~~~~~~~~
993(                         # COSE_Encrypt0_Tagged
  [
    h'a20444a1534e3c0641a3', # protected:
                               {04:h'a1534e3c',
                                06:h'a3'}
    {},                      # unprotected
    TAG                      # ciphertext + truncated 8-byte TAG
  ]
)
~~~~~~~~~~~
{: artwork-align="center"}

This COSE object encodes to a total size of 25 bytes.

{{comp-aes-ccm}} summarizes these results.

~~~~~~~~~~~
+----------------------+-----+-----+---------+------------+
|       Structure      | Tid | TAG | COSE OH | Message OH |
+----------------------+-----+-----+---------+------------+
| COSE_Encrypt0_Tagged | 5 B | 8 B |   12 B  |  25 bytes  |
+----------------------+-----+-----+---------+------------+
~~~~~~~~~~~
{: #comp-aes-ccm title="Message overhead for a 5-byte Tid using AES_128_CCM_8."}
{: artwork-align="center"}

## Symmetric Encryption with Asymmetric Signature (SEAS) {#sem-seds}

This example is based on AES-CCM and ECDSA with 64 bytes signature. The same assumption on the security context as in {{sem-auth-enc}}.
COSE defines the field 'counter signature w/o headers' that is used here to sign a COSE_Encrypt0_Tagged message (see Section 3 of {{I-D.ietf-cose-msg}}).

The object in COSE encoding gives:

~~~~~~~~~~~
993(                         # COSE_Encrypt0_Tagged
  [
    h'a20444a1534e3c0641a3', # protected:
                               {04:h'a1534e3c',
                                06:h'a3'}
    {9:SIG},                 # unprotected: 
                                09: 64 bytes signature
    TAG                      # ciphertext + truncated 8-byte TAG
  ]
)
~~~~~~~~~~~
{: artwork-align="center"}

This COSE object encodes to a total size of 92 bytes.

{{comp-aes-ccm-ecdsa}} summarizes these results.

~~~~~~~~~~~
+----------------------+-----+-----+------+---------+------------+
|       Structure      | Tid | TAG | SIG  | COSE OH | Message OH |
+----------------------+-----+-----+------+---------+------------+
| COSE_Encrypt0_Tagged | 5 B | 8 B | 64 B |   15 B  |    92 B    |
+----------------------+-----+-----+------+---------+------------+
~~~~~~~~~~~
{: #comp-aes-ccm-ecdsa title="Message overhead for a 5-byte Tid using AES-CCM countersigned with ECDSA."}
{: artwork-align="center"}

--- fluff
