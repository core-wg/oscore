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
  RFC8132:
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

# Introduction {#intro}

The Constrained Application Protocol (CoAP) is a web application protocol, designed for constrained nodes and networks {{RFC7228}}. CoAP specifies the use of proxies for scalability and efficiency. At the same time CoAP {{RFC7252}} references DTLS {{RFC6347}} for security. CoAP proxies require DTLS to be terminated at the proxy. The proxy therefore not only has access to the data required for performing the intended proxy functionality, but is also able to eavesdrop on, or manipulate any part of the CoAP payload and metadata, in transit between client and server. The proxy can also inject, delete, or reorder packages since they are no longer protected by DTLS.

This document defines the security protocol Object Security of CoAP (OSCOAP), protecting CoAP requests and responses end-to-end across intermediary nodes such as CoAP forward proxies and cross-protocols translations including HTTP-to-CoAP proxies {{RFC8075}}. In addition to the core features defined in {{RFC7252}}, OSCOAP supports Observe {{RFC7641}} and Blockwise {{RFC7959}}. An analysis of end-to-end security for CoAP messages through some types of intermediary nodes is performed in {{I-D.hartke-core-e2e-security-reqs}}. OSCOAP protects the CoAP Request/Response layer only, and not the Messaging Layer (Section 2 of {{RFC7252}}). Therefore, all the messages mentioned in this document refer to non-empty CON, NON, and ACK messages. Additionally, since the message formats for CoAP over unreliable transport {{RFC7252}} and for CoAP over reliable transport {{I-D.ietf-core-coap-tcp-tls}} differ only in terms of Messaging Layer, OSCOAP can be applied to both unreliable and reliable transport. 

OSCOAP is designed for constrained nodes and networks and provides an in-layer security protocol for CoAP which does not depend on underlying layers. OSCOAP can be used anywhere where CoAP can be used, including non-IP transport {{I-D.bormann-6lo-coap-802-15-ie}}. An extension of OSCOAP may also be used to protect group communication for CoAP {{I-D.tiloca-core-multicast-oscoap}}. The use of OSCOAP does not affect the URI scheme and OSCOAP can therefore be used with any URI scheme defined for CoAP. The application decides the conditions for which OSCOAP is required. 

OSCOAP builds on CBOR Object Signing and Encryption (COSE) {{RFC8152}}, providing end-to-end encryption, integrity, replay protection, and secure message binding. A compressed version of COSE is used, see {{compression}}. The use of OSCOAP is signaled with the CoAP option Object-Security, defined in {{option}}. OSCOAP is designed to protect as much information as possible, while still allowing proxy operations ({{proxy-operations}}). OSCOAP provides protection of CoAP payload, most options, and non-message layer header fields. The solution transforms a CoAP message into an "OSCOAP message" before sending, and vice versa after receiving. The OSCOAP message is a CoAP message related to the original CoAP message in the following way: the original CoAP message payload (if present), options not processed by a proxy, and the request/response method (CoAP Code) are protected in a COSE object. The message fields of the original messages that are encrypted are not present in the OSCOAP message, and instead the Object-Security option and the compressed COSE object are added, see {{fig-sketch}}.

~~~~~~~~~~~
Client                                            Server
   |  OSCOAP request:                               |
   |    POST example.com                            |
   |      Header, Token,                            |
   |      Options: {Object-Security:-, ...},        |
   |      Payload: Compressed COSE object           |
   +----------------------------------------------->|
   |  OSCOAP response:                              |
   |    2.04 (Changed)                              |
   |      Header, Token,                            |
   |      Options: {Object-Security:-, ...},        |
   |      Payload: Compressed COSE object           |
   |<-----------------------------------------------+
   |                                                |
~~~~~~~~~~~
{: #fig-sketch title="Sketch of OSCOAP" artwork-align="center"}

OSCOAP may be used in very constrained settings, thanks to its small message size and the restricted code and memory requirements in addition to what is required by CoAP. OSCOAP can be combined with transport layer security such as DTLS or TLS, thereby enabling end-to-end security of e.g. CoAP Payload, Options and Code, in combination with hop-by-hop protection of the Messaging Layer, during transport between end-point and intermediary node. Examples of the use of OSCOAP are given in {{examples}}.

An implementation supporting this specification MAY only implement the client part, MAY only implement the server part, or MAY only implement one of the proxy parts. OSCOAP is designed to work with legacy CoAP-to-CoAP forward proxies {{RFC7252}}, but an OSCOAP aware proxy will be more efficient. HTTP-to-CoAP proxies {{RFC8075}} and CoAP-to-HTTP proxies need to implement respective part of this specification to work with OSCOAP (see {{proxy-operations}}).

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}. These words may also appear in this document in lowercase, absent their normative meanings.

Readers are expected to be familiar with the terms and concepts described in CoAP {{RFC7252}}, Observe {{RFC7641}}, Blockwise {{RFC7959}}, COSE {{RFC8152}}, CBOR {{RFC7049}}, CDDL {{I-D.greevenbosch-appsawg-cbor-cddl}}, and constrained environments {{RFC7228}}.

The terms Common/Sender/Recipient Context, Master Secret/Salt, Sender ID/Key, Recipient ID/Key, and Common IV are defined in {{context-definition}}.

# The Object-Security Option {#option}

The Object-Security option (see {{fig-option}}) indicates that the CoAP message is an OSCOAP message and that it contains a compressed COSE object (see {{cose-object}} and {{compression}}). The Object-Security option is critical, safe to forward, part of the cache key, and not repeatable. 

~~~~~~~~~~~
+-----+---+---+---+---+-----------------+--------+--------+---------+
| No. | C | U | N | R | Name            | Format | Length | Default | 
+-----+---+---+---+---+-----------------+--------+--------+---------+
| TBD | x |   |   |   | Object-Security | empty  | 0      | (none)  |
+-----+---+---+---+---+-----------------+--------+--------+---------+
   C = Critical,  U = Unsafe,  N = NoCacheKey,  R = Repeatable   
~~~~~~~~~~~
{: #fig-option title="The Object-Security Option" artwork-align="center"}

The Object-Security option SHALL be empty (length zero), and the payload of the OSCOAP message is the compressed COSE object. An endpoint receiving a non-empty Object-Security option SHALL treat it as malformed and reject it. An endpoint receiving a CoAP message without payload, that also contains an Object-Security option SHALL treat it as malformed and reject it. A successful response to a request with the Object-Security option SHALL contain the Object-Security option. 

Since the payload and most options are encrypted {{protected-fields}}, and the corresponding plain text message fields of the original are not included in the OSCOAP message, the processing of these fields does not expand the total message size.

A CoAP proxy SHOULD NOT cache a response to a request with an Object-Security option, since the response is only applicable to the original client's request, see {{coap-coap-proxy}}. As the compressed COSE Object is included in the cache key, messages with the Object-Security option will never generate cache hits. For Max-Age processing, see {{max-age}}.

# The Security Context {#context}

OSCOAP requires that client and server establish a shared security context used to process the COSE objects. OSCOAP uses COSE with an Authenticated Encryption with Additional Data (AEAD) algorithm for protecting CoAP message data between a CoAP client and a CoAP server. In this section, we define the security context and how it is derived in client and server based on a common shared master secret and a key derivation function (KDF).

## Security Context Definition {#context-definition}

The security context is the set of information elements necessary to carry out the cryptographic operations in OSCOAP. For each endpoint, the security context is composed of a "Common Context", a "Sender Context", and a "Recipient Context".

The endpoints protect messages to send using the Sender Context and verify messages received using the Recipient Context, both contexts being derived from the Common Context and other data. Clients need to be able to retrieve the correct security context to use.

An endpoint uses its Sender ID (SID) to derive its Sender Context, and the other endpoint uses the same ID, now called Recipient ID (RID), to derive its Recipient Context. In communication between two endpoints, the Sender Context of one endpoint matches the Recipient Context of the other endpoint, and vice versa. Thus, the two security contexts identified by the same IDs in the two endpoints are not the same, but they are partly mirrored. Retrieval and use of the security context are shown in {{fig-context}}.

~~~~~~~~~~~
              .-------------.           .-------------.
              |  Common,    |           |  Common,    |
              |  Sender,    |           |  Recipient, |
              |  Recipient  |           |  Sender     |
              '-------------'           '-------------'
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

* Key Derivation Function. The HMAC based HKDF used to derive Sender Key, Recipient Key, and Common IV.

* Master Secret. Variable length, uniformly random byte string containing the key used to derive traffic keys and IVs. Its value is immutable once the security context is established.

* Master Salt (OPTIONAL). Variable length byte string containing the salt used to derive traffic keys and IVs. Its value is immutable once the security context is established.

* Common IV. Byte string derived from Master Secret and Master Salt. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

The Sender Context contains the following parameters:

* Sender ID. Non-negative integer used to identify the Sender Context and to assure unique nonces. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Sender Key. Byte string containing the symmetric key to protect messages to send. Derived from Common Context and Sender ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Sender Sequence Number. Non-negative integer used by the sender to protect requests and Observe notifications. Used as partial IV {{RFC8152}} to generate unique nonces for the AEAD. Maximum value is determined by the AEAD Algorithm.

The Recipient Context contains the following parameters:

* Recipient ID. Non-negative integer used to identify the Recipient Context and to assure unique nonces. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Recipient Key. Byte string containing the symmetric key to verify messages received. Derived from Common Context and Recipient ID. Length is determined by the AEAD Algorithm. Its value is immutable once the security context is established.

* Replay Window (Server only). The replay window to verify requests received.

An endpoint may free up memory by not storing the Common IV, Sender Key, and Recipient Key, deriving them from the Master Key and Master Salt when needed. Alternatively, an endpoint may free up memory by not storing the Master Secret and Master Salt after the other parameters have been derived.

The endpoints MAY interchange the client and server roles while maintaining the same security context. When this happens, the former server still protects messages to send using its Sender Context, and verifies messages received using its Recipient Context. The same is also true for the former client. The endpoints MUST NOT change the Sender/Recipient ID when changing roles. In other words, changing the roles does not change the set of keys to be used.

## Establishment of Security Context Parameters {#context-derivation}

The parameters in the security context are derived from a small set of input parameters. The following input parameters SHALL be pre-established:

* Master Secret

* Sender ID 

* Recipient ID 

The following input parameters MAY be pre-established. In case any of these parameters is not pre-established, the default value indicated below is used:

* AEAD Algorithm (alg)

   - Default is AES-CCM-16-64-128 (COSE abbreviation: 10)

* Master Salt

   - Default is the empty string

* Key Derivation Function (KDF)

   - Default is HKDF SHA-256

* Replay Window Type and Size

   - Default is DTLS-type replay protection with a window size of 32 ({{RFC6347}})

All input parameters need to be known to and agreed on by both endpoints, but the replay window may be different in the two endpoints. The replay window type and size is used by the client in the processing of the Request-Tag {{I-D.amsuess-core-repeat-request-tag}}. How the input parameters are pre-established, is application specific. The ACE framework may be used to establish the necessary input parameters {{I-D.ietf-ace-oauth-authz}}. 

### Derivation of Sender Key, Recipient Key, and Common IV 

The KDF MUST be one of the HMAC based HKDF {{RFC5869}} algorithms defined in COSE. HKDF SHA-256 is mandatory to implement. The security context parameters Sender Key, Recipient Key, and Common IV SHALL be derived from the input parameters using the HKDF, which consists of the composition of the HKDF-Extract and HKDF-Expand steps ({{RFC5869}}):

~~~~~~~~~~~
   output parameter = HKDF(salt, IKM, info, L) 
~~~~~~~~~~~

where:

* salt is the Master Salt as defined above
* IKM is the Master Secret is defined above
* info is a CBOR array consisting of:

~~~~~~~~~~~ CDDL
   info = [
       id : uint / nil,
       alg : int,
       type : tstr,
       L : uint
   ]
~~~~~~~~~~~
~~~~~~~~~~~
   * id is the Sender ID or Recipient ID when deriving keys and nil when deriving the Common IV.

   * type is "Key" or "IV"
~~~~~~~~~~~

* L is the size of the key/IV for the AEAD algorithm used, in octets.

For example, if the algorithm AES-CCM-16-64-128 (see Section 10.2 in {{RFC8152}}) is used, the value for L is 16 for keys and 13 for the Common IV.

### Initial Sequence Numbers and Replay Window {#initial-replay}

The Sender Sequence Number is initialized to 0.  The supported types of replay protection and replay window length is application specific and depends on the lower layers. Default is DTLS-type replay protection with a window size of 32 initiated as described in Section 4.1.2.6 of {{RFC6347}}. 

## Requirements on the Security Context Parameters

As collisions may lead to the loss of both confidentiality and integrity, Sender ID SHALL be unique in the set of all security contexts using the same Master Secret and Master Salt. When a trusted third party assigns identifiers (e.g. using {{I-D.ietf-ace-oauth-authz}}) or by using a protocol that allows the parties to negotiate locally unique identifiers in each endpoint, the Sender IDs can be very short. The maximum Sender ID is 2^(nonce length in bits - 48) - 1, For AES-CCM-16-64-128 the maximum Sender ID is 2^56 - 1. If Sender ID uniqueness cannot be guaranteed, random Sender IDs MUST be used. Random Sender IDs MUST be long enough so that the probability of collisions is negligible.

To enable retrieval of the right Recipient Context, the Recipient ID SHOULD be unique in the sets of all Recipient Contexts used by an endpoint.

While the triple (Master Secret, Master Salt, Sender ID) MUST be unique, the same Master Salt MAY be used with several Master Secrets and the same Master Secret MAY be used with several Master Salts.

# Protected CoAP Message Fields {#protected-fields} 

OSCOAP transforms a CoAP message into an OSCOAP message, and vice versa. OSCOAP protects as much of the original CoAP message as possible while still allowing certain proxy operations (see {{proxy-operations}}). This section defines how OSCOAP protects the CoAP message fields and transfers them between CoAP client and CoAP server (in any direction).  

Message fields of the original CoAP message may be protected end-to-end between CoAP client and CoAP server in different ways:

* Class E: encrypted and integrity protected, 
* Class I: integrity protected only, or
* Class U: unprotected.

The sending endpoint SHALL transfer Class E message fields in the ciphertext of the COSE object in the OSCOAP message. The sending endpoint SHALL include Class I message fields in the Additional Authenticated Data (AAD) of the AEAD algorithm, allowing the receiving endpoint to detect if the value has changed in transfer. Class U message fields SHALL NOT be protected in transfer. Class I and Class U message field values are transferred in the header or options part of the OSCOAP message which is visible to proxies.

Message fields not visible to proxies, i.e. transported in the ciphertext of the COSE object, are called "Inner". Message fields transferred in the header or options part of the OSCOAP message, which is visible to proxies, are called "Outer".

CoAP message fields are either Inner or Outer: Inner if the value is intended for the destination endpoint, Outer if the value is intended for a proxy. An OSCOAP message may contain both an Inner and an Outer message field of certain CoAP message fields. Inner and Outer message fields are processed independently.

## CoAP Payload

The CoAP Payload, if present in the original message, SHALL be encrypted and integrity protected and is thus a Class E message field. The sending endpoint writes the payload of the original CoAP message into the plaintext ({{plaintext}}) input to the COSE object. The receiving endpoint verifies and decrypts the COSE object, and recreates the payload of the original CoAP message.


## CoAP Options {#coap-options}

A summary of how options are protected is shown in {{fig-option-protection}}. Options which require special processing, in particular those which may be both Inner and Outer, are denoted by '*'.

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
| 14 | Max-Age        | * |   | * |
| 15 | Uri-Query      | x |   |   |
| 17 | Accept         | x |   |   |
| 20 | Location-Query | x |   |   |
| 23 | Block2         | * |   | * |
| 27 | Block1         | * |   | * |
| 28 | Size2          | * |   | * |
| 35 | Proxy-Uri      | * |   | * |
| 39 | Proxy-Scheme   |   |   | x |
| 60 | Size1          | * |   | * |
+----+----------------+---+---+---+

 E = Encrypt and Integrity Protect (Inner)
 I = Integrity Protect only (Outer)
 U = Unprotected (Outer)
 * = Special
~~~~~~~~~~~
{: #fig-option-protection title="Protection of CoAP Options" artwork-align="center"}

Unless specified otherwise, CoAP options not listed in {{fig-option-protection}} SHALL be of class E.

Specifications of new CoAP options SHOULD define how they are processed with OSCOAP. A new COAP option SHOULD be of class E unless it requires proxy processing.

### Inner Options {#inner-options}

When using OSCOAP, Inner options (marked with 'x' in column E of {{fig-option-protection}}) are sent in a way analogous to communicating in a protected manner directly with the other endpoint.

The sending endpoint SHALL write the class E options present in the original CoAP message into the plaintext of the COSE object {{plaintext}}, and then remove the class E options from the OSCOAP message. 

The processing of Inner options by the receiving endpoint is specified in {{ver-req}} and {{ver-res}}.

### Outer Options {#outer-options}

Outer options (marked with 'x' in column U or I of {{fig-option-protection}}) are used to support proxy operations. 

The sending endpoint SHALL include the class U and class I options present in the original message to the options part of the OSCOAP message. Class I options (marked with 'x' in column I of {{fig-option-protection}}) SHALL be integrity protected between the endpoints as specified in {{AAD}}. All Outer options, including the Object-Security option, SHALL be encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included outer option value. 

The processing of Outer options by the receiving endpoint is specified in {{ver-req}} and {{ver-res}}.

### Special Options

Some options require special processing, marked with an asterisk ('*') in {{fig-option-protection}}. An asterisk in the columns E and U indicate that the option may be added as an Inner and/or Outer message by the sending endpoint; the processing is specified in this section.

#### Max-Age {#max-age}

The Inner Max-Age option is used to specify the freshness (as defined in {{RFC7252}}) of the resource, end-to-end from the server to the client, taking into account that the option is not accessible to proxies. The Inner Max-Age SHALL be processed by OSCOAP as specified in {{inner-options}}.

The Outer Max-Age option is used to avoid unnecessary caching of OSCOAP responses at OSCOAP unaware intermediary nodes. A server MAY set a Class U Max-Age option with value zero to Observe responses (see Section 5.6.1 of {{RFC7252}}) and process it according to {{outer-options}}. The Outer Max-Age option value SHALL be discarded by the OSCOAP client.


#### The Block Options {#block-options}

Blockwise {{RFC7959}} is an optional feature. An implementation MAY support {{RFC7252}} and the Object-Security option without supporting {{RFC7959}}. The Block options are used to secure message fragmentation end-to-end (Inner options) or for proxies to fragment the message for the next hop (Outer options).


##### Inner Block Options {#inner-block-options}

The sending CoAP endpoint MAY fragment a CoAP message as defined in {{RFC7959}} before the message is processed by OSCOAP. In this case the Block options SHALL be processed by OSCOAP as Inner options ({{inner-options}}). The receiving CoAP endpoint SHALL process the OSCOAP message according to {{inner-options}} before processing blockwise as defined in {{RFC7959}}.

For blockwise request operations using Block1, an endpoint MUST comply with the Request-Tag processing defined in Section 3 of {{I-D.amsuess-core-repeat-request-tag}}. In particular, the rules in section 3.3.1 of {{I-D.amsuess-core-repeat-request-tag}} MUST be followed, which guarantee that a specific request body is assembled only from the corresponding request blocks.

For blockwise response operations using Block2, an endpoint MUST comply with the ETag processing defined in Section 4 of {{I-D.amsuess-core-repeat-request-tag}}.


##### Outer Block Options

Proxies MAY fragment an OSCOAP message using {{RFC7959}}, which then introduces Outer Block options not generated by the sending endpoint. Note that the Outer Block options are neither encrypted nor integrity protected. As a consequence, a proxy can maliciously inject block fragments indefinitely, since the receiving endpoint needs to receive the last block (see {{RFC7959}}) to be able to compose the OSCOAP message and verify its integrity. Therefore, applications supporting OSCOAP and {{RFC7959}} MUST specify a security policy defining a maximum unfragmented message size (MAX_UNFRAGMENTED_SIZE) considering the maximum size of message which can be handled by the endpoints. Messages exceeding this size SHOULD be fragmented by the sending endpoint using Inner Block options ({{inner-block-options}}).

An endpoint receiving an OSCOAP message with an Outer Block option SHALL first process this option according to {{RFC7959}}, until all blocks of the OSCOAP message have been received, or the cumulated message size of the blocks exceeds MAX_UNFRAGMENTED_SIZE.  In the former case, the processing of the OSCOAP message continues as defined in this document. In the latter case the message SHALL be discarded.

To allow multiple concurrent request operations to the same server (not only same resource), a CoAP proxy SHOULD follow the Request-Tag processing specified in section 3.3.2 of {{I-D.amsuess-core-repeat-request-tag}}.

 
#### Proxy-Uri

Proxy-Uri, when present, is split by OSCOAP into class U options and class E options, which are processed accordingly. When Proxy-Uri is used in the original CoAP message, Uri-* are not present {{RFC7252}}.

The sending endpoint SHALL first decompose the Proxy-Uri value of the original CoAP message into the Proxy-Scheme, Uri-Host, Uri-Port, Uri-Path, and Uri-Query options (if present) according to section 6.4 of {{RFC7252}}. 

Uri-Path and Uri-Query are class E options and SHALL be protected and processed as Inner options ({{inner-options}}). 

The Proxy-Uri option of the OSCOAP message SHALL be set to the composition of Proxy-Scheme, Uri-Host and Uri-Port options (if present) as specified in section 6.5 of {{RFC7252}}, and processed as an Outer option of Class U ({{outer-options}}).

Note that replacing the Proxy-Uri value with the Proxy-Scheme and Uri-* options works by design for all CoAP URIs (see Section 6 of {{RFC7252}}. OSCOAP-aware HTTP servers should not use the userinfo component of the HTTP URI (as defined in section 3.2.1. of {{RFC3986}}), so that this type of replacement is possible in the presence of CoAP-to-HTTP proxies. In other documents specifying cross-protocol proxying behavior using different URI structures, it is expected that the authors will create Uri-* options that allow decomposing the Proxy-Uri, and specify in which OSCOAP class they belong.

An example of how Proxy-Uri is processed is given here. Assume that the original CoAP message contains:

* Proxy-Uri = "coap://example.com/resource?q=1"

During OSCOAP processing, Proxy-Uri is split into:

* Proxy-Scheme = "coap"
* Uri-Host = "example.com"
* Uri-Port = "5683"
* Uri-Path = "resource"
* Uri-Query = "q=1"

Uri-Path and Uri-Query follow the processing defined in {{inner-options}}, and are thus encrypted and transported in the COSE object. The remaining options are composed into the Proxy-Uri included in the options part of the OSCOAP message, which has value:

* Proxy-Uri = "coap://example.com"

(See Section 6.1 of {{RFC7252}})

#### Observe {#observe}

Observe {{RFC7641}} is an optional feature. An implementation MAY support {{RFC7252}} and the Object-Security option without supporting {{RFC7641}}. The Observe option as used here targets the requirements on forwarding of {{I-D.hartke-core-e2e-security-reqs}} (Section 2.2.1.2).

In order for an OSCOAP-unaware proxy to support forwarding of Observe messages ({{RFC7641}}), there SHALL be an Outer Observe option, i.e. present in the options part of the OSCOAP message. The processing of the CoAP Code for Observe messages is described in {{coap-header}}.

To secure the order of notifications, the client SHALL maintain a Notification Number for each Observation it registers. The Notification Number is a non-negative integer containing the largest Partial IV of the successfully received notifications for the associated Observe registration, see {{replay-protection}}. The Notification Number is initialized to the Partial IV of the first successfully received notification. In contrast to {{RFC7641}}, the received partial IV MUST always be compared with the Notification Number, which thus MUST NOT be forgotten after 128 seconds.

If the verification fails, the client SHALL stop processing the response, and in the case of CON respond with an empty ACK. The client MAY ignore the Observe option value.

The Observe option in the CoAP request may be legitimately removed by a proxy. If the Observe option is removed from a CoAP request by a proxy, then the server can still verify the request (as a non-Observe request), and produce a non-Observe response. If the OSCOAP client receives a response to an Observe request without an outer Observe value, then it MUST verify the response as a non-Observe response. (The reverse case is covered in the verification of the response, see {{processing}}.)

## CoAP Header {#coap-header}

Most CoAP header fields are required to be read and/or changed by CoAP proxies and thus cannot in general be protected end-to-end between the endpoints. As mentioned in {{intro}}, OSCOAP protects the CoAP Request/Response layer only, and not the Messaging Layer (Section 2 of {{RFC7252}}), so fields such as Type and Message ID are not protected with OSCOAP. 

The CoAP header field Code is protected by OSCOAP. Code SHALL be encrypted and integrity protected (Class E) to prevent an intermediary from eavesdropping or manipulating the Code (e.g. changing from GET to DELETE). 

The sending endpoint SHALL write the Code of the original CoAP message into the plaintext of the COSE object {{plaintext}}. After that, the Outer Code of the OSCOAP message SHALL be set to 0.02 (POST) for requests and to 2.04 (Changed) for responses, except for Observe messages. For Observe messages, the Outer Code of the OSCOAP message SHALL be set to 0.05 (FETCH) for requests and to 2.05 (Content) for responses. The exception allows OSCOAP to be compliant with the Observe processing in OSCOAP-unaware proxies. The choice of POST and FETCH allows all OSCOAP messages to have payload.

The receiving endpoint SHALL discard the Code in the OSCOAP message and write the Code of the Plaintext in the COSE object ({{plaintext}}) into the decrypted CoAP message.

The other CoAP header fields are Unprotected (Class U). The sending endpoint SHALL write all other header fields of the original message into the header of the OSCOAP message. The receiving endpoint SHALL write the header fields from the received OSCOAP message into the header of the decrypted CoAP message.

# The COSE Object {#cose-object}

This section defines how to use COSE {{RFC8152}} to wrap and protect data in the original CoAP message. OSCOAP uses the untagged COSE_Encrypt0 structure with an Authenticated Encryption with Additional Data (AEAD) algorithm. The key lengths, IV length, nonce length, and maximum Sender Sequence Number are algorithm dependent.
 
The AEAD algorithm AES-CCM-16-64-128 defined in Section 10.2 of {{RFC8152}} is mandatory to implement. For AES-CCM-16-64-128 the length of Sender Key and Recipient Key is 128 bits, the length of nonce and Common IV is 13 bytes. The maximum Sender Sequence Number is specified in {{sec-considerations}}.

We denote by Plaintext the data that is encrypted and integrity protected, and by Additional Authenticated Data (AAD) the data that is integrity protected only.

The COSE Object SHALL be a COSE_Encrypt0 object with fields defined as follows

- The "protected" field is empty.

- The "unprotected" field includes:

   * The "Partial IV" parameter. The value is set to the Sender Sequence Number. The Partial IV SHALL be of minimum length needed to encode the Sender Sequence Number. This parameter SHALL be present in requests. In case of Observe ({{observe}}) the Partial IV SHALL be present in responses, and otherwise the Partial IV SHALL NOT be present in responses.

   * The "kid" parameter. The value is set to the Sender ID (see {{context}}). This parameter SHALL be present in requests and SHALL NOT be present in responses.

-  The "ciphertext" field is computed from the secret key (Sender Key or Recipient Key), Nonce (see {{nonce}}), Plaintext (see {{plaintext}}), and the Additional Authenticated Data (AAD) (see {{AAD}}) following Section 5.2 of {{RFC8152}}.

The encryption process is described in Section 5.3 of {{RFC8152}}.

## Nonce {#nonce}

The nonce is constructed by padding the partial IV (in network byte order) with zeroes to exactly 6 bytes, padding the Sender ID of the endpoint that generated the Partial IV (in network byte order) with zeroes to exactly nonce length – 6 bytes, concatenating the padded partial IV with the padded ID, and then XORing with the Common IV.

When observe is not used, the request and the response uses the same nonce. In this way, the partial IV does not have to be sent, which reduces the size of the response. For detailed processing instructions, see {{processing}}.

~~~~~~~~~~~
+-----------------------+--+--+--+--+--+--+
|  ID of PIV generator  |   Partial IV    |---+ 
+-----------------------+--+--+--+--+--+--+   | 
                                              | 
+-----------------------------------------+   | 
|                Common IV                |->(+)
+-----------------------------------------+   | 
                                              | 
+-----------------------------------------+   | 
|                  Nonce                  |<--+ 
+-----------------------------------------+     
~~~~~~~~~~~
{: #fig-nonce title="Nonce Formation" artwork-align="center"}

## Plaintext {#plaintext}

The Plaintext is formatted as a CoAP message without Header (see {{fig-plaintext}}) consisting of:

- the Code of the original CoAP message as defined in Section 3 of {{RFC7252}}; and

- all Class E option values (see {{inner-options}}) present in the original CoAP message (see {{coap-options}}). The options are encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included Class E option; and

- the Payload of original CoAP message, if present, and in that case prefixed by the one-byte Payload Marker (0xFF).

~~~~~~~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |    Class E options (if any) ...                             
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
   options : bstr,
   alg : int,
   request_kid : bstr,
   request_piv : bstr
]
~~~~~~~~~~~

where:

- version: contains the OSCOAP version number. Implementations of this specification MUST set this field to 1. Other values are reserved for future versions.

- options: contains the Class I options (see {{outer-options}}) present in the original CoAP message encoded as described in Section 3.1 of {{RFC7252}}, where the delta is the difference to the previously included class I option.

- alg: contains the AEAD Algorithm from the security context used for the exchange (see {{context-definition}}).

- request_kid: contains the value of the 'kid' in the COSE object of the request (see Section 5).

- request_piv: contains the value of the 'Partial IV' in the COSE object of the request (see Section 5).

# Sequence Numbers, Replay, Message Binding, and Freshness {#sequence-numbers}

## Message Binding

In order to prevent response delay and mismatch attacks {{I-D.mattsson-core-coap-actuators}} from on-path attackers and compromised proxies, OSCOAP binds responses to the request by including the request's ID (Sender ID or Recipient ID) and partial IV in the AAD of the response. The server therefore needs to store the request's ID (Sender ID or Recipient ID) and partial IV until all responses have been sent.

## AEAD Nonce Uniqueness {#nonce-uniqueness}

An AEAD nonce MUST NOT be used more than once per AEAD key. In order to assure unique nonces, each Sender Context contains a Sender Sequence Number used to protect requests, and - in case of Observe - responses. If messages are processed concurrently, the operation of reading and increasing the Sender Sequence Number MUST be atomic.

The maximum Sender Sequence Number is algorithm dependent, see {{sec-considerations}}. If the Sender Sequence Number exceeds the maximum, the endpoint MUST NOT process any more messages with the given Sender Context. The endpoint SHOULD acquire a new security context (and consequently inform the other endpoint) before this happens. The latter is out of scope of this document.

## Freshness

For requests, OSCOAP provides weak absolute freshness as the only guarantee is that the request is not older than the security context. For applications having stronger demands on request freshness (e.g. control of actuators), OSCOAP needs to be augmented with mechanisms providing freshness {{I-D.amsuess-core-repeat-request-tag}}.

For responses, the message binding guarantees that a response is not older than its request. For responses without Observe, this gives strong absolute freshness. For responses with Observe, the absolute freshness gets weaker with time, and it is RECOMMENDED that the client regularly restart the observation.

For requests, and responses with Observe, OSCOAP also provides relative freshness in the sense that the received Partial IV allows a recipient to determine the relative order of responses.

## Replay Protection {#replay-protection}

In order to protect from replay of requests, the server's Recipient Context includes a Replay Window. A server SHALL verify that a Partial IV received in the COSE object has not been received before. If this verification fails and the message received is a CON message, the server SHALL respond with a 5.03 Service Unavailable error message with the inner Max-Age option set to 0. The diagnostic payload MAY contain the "Replay protection failed" string. The size and type of the Replay Window depends on the use case and lower protocol layers. In case of reliable and ordered transport from endpoint to endpoint, the server MAY just store the last received Partial IV and require that newly received Partial IVs equals the last received Partial IV + 1.

Responses to non-Observe requests are protected against replay as they are cryptographically bound to the request. 

In the case of Observe, a client receiving a notification SHALL verify that the Partial IV of a received notification is greater than the Notification Number bound to that Observe registration. If the verification fails, the client SHALL stop processing the response, and in the case of CON respond with an empty ACK. If the verification succeeds, the client SHALL overwrite the corresponding Notification Number with the received Partial IV. 

If messages are processed concurrently, the partial IV needs to be validated a second time after decryption and before updating the replay protection data. The operation of validating the partial IV and updating the replay protection data MUST be atomic.

## Losing Part of the Context State {#context-state}

To prevent reuse of the Nonce with the same key, or from accepting replayed messages, a node needs to handle the situation of losing rapidly changing parts of the context, such as the request Token, Sender Sequence Number, Replay Window, and Nofitifcation Numbers. These are typically stored in RAM and therefore lost in the case of an unplanned reboot.

After boot, a node MAY reject to use existing security contexts from before it booted and MAY establish a new security context with each party it communicates. However, establishing a fresh security context may have a non-negligible cost in terms of e.g. power consumption.

After boot, a node MAY use a partly persistently stored security context, but then the node MUST NOT reuse a previous Sender Sequence Number and MUST NOT accept previously accepted messages. Some ways to achieve this is described below:

### Sequence Number

To prevent reuse of Sender Sequence Numbers, a node MAY perform the following procedure during normal operations:

* Each time the Sender Sequence Number is evenly divisible by K, where K is a positive integer, store the Sender Sequence Number in persistent memory. After boot, the node initiates the Sender Sequence Number to the value stored in persistent memory + K - 1. Storing to persistent memory can be costly. The value K gives a trade-off between the number of storage operations and efficient use of Sender Sequence Numbers.

### Replay Window

To prevent accepting replay of previously received requests, the server MAY perform the following procedure after boot:

* For each stored security context, the first time after boot the server receives an OSCOAP request, the server uses the Repeat option {{I-D.amsuess-core-repeat-request-tag}} to get a request with verifiable freshness and uses that to synchronize the replay window. If the server can verify the fresh request, the partial IV in the fresh request is set as the lower limit of the replay window.

### Replay Protection of Observe Notifications

To prevent accepting replay of previously received notification responses, the client MAY perform the following procedure after boot:

* The client rejects notifications bound to the earlier registration, removes all Notification Numbers and re-register using Observe.

# Processing {#processing}

This section describes the OSCOAP message processing. An illustration of the nonce generation used in the processing is given in {{nonce-generation}}.

## Protecting the Request {#prot-req}

Given a CoAP request, the client SHALL perform the following steps to create an OSCOAP request:

1. Retrieve the Sender Context associated with the target resource.

2. Compose the Additional Authenticated Data, as described in {{cose-object}}.

3. Compute the AEAD nonce by XORing the Common IV with the partial IV (Sender Sequence Number in network byte order). Then (in one atomic operation, see {{nonce-uniqueness}}) increment the Sender Sequence Number by one.

4. Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in {{compression}}.

5. Format the OSCOAP message according to {{protected-fields}}. The Object-Security option is added, see {{outer-options}}.

6. Store the association Token - Security Context. The client SHALL be able to find the Recipient Context from the Token in the response.

## Verifying the Request {#ver-req}

A server receiving a request containing the Object-Security option SHALL perform the following steps:

1. Process outer Block options according to {{RFC7959}}, until all blocks of the request have been received, see {{block-options}}.

2. Discard the message Code and all Outer options of Class non I and non U from the message. For example, If-Match Outer option is discarded, Uri-Host Outer option is not discarded.

3. Decompress the COSE Object ({{compression}}) and retrieve the Recipient Context associated with the Recipient ID in the 'kid' parameter. If the request is a NON message and either the decompression or the COSE message fails to decode, or the server fails to retrieve a Recipient Context with Recipient ID corresponding to the 'kid' parameter received, then the server SHALL stop processing the request. If the request is a CON message, and:

   * either the decompression or the COSE message fails to decode, the server SHALL respond with a 4.02 Bad Option error message. The diagnostic payload SHOULD contain the string "Failed to decode COSE".
   
   * the server fails to retrieve a Recipient Context with Recipient ID corresponding to the 'kid' parameter received, the server SHALL respond with a 4.01 Unauthorized error message. The diagnostic payload MAY contain the string "Security context not found".

4. Verify the 'Partial IV' parameter using the Replay Window, as described in {{sequence-numbers}}.

5. Compose the Additional Authenticated Data, as described in {{cose-object}}.

6. Compute the AEAD nonce by XORing the Common IV with the padded 'Partial IV' parameter, received in the COSE Object.

7. Decrypt the COSE object using the Recipient Key.

   * If decryption fails, the server MUST stop processing the request and, if the request is a CON message, the server MUST respond with a 4.00 Bad Request error message. The diagnostic payload MAY contain the "Decryption failed" string.

   * If decryption succeeds, update the Replay Window, as described in {{sequence-numbers}}.

8. For each decrypted option, check if the option is also present as an Outer option: if it is, discard the Outer. For example: the message contains a Content-Format Inner and a Content-Format Outer option. The Outer Content-Format is discarded.

9. Add decrypted code, options and payload to the decrypted request. The Object-Security option is removed.

10. The decrypted CoAP request is processed according to {{RFC7252}}

## Protecting the Response {#prot-res}

Given a CoAP response, the server SHALL perform the following steps to create an OSCOAP response. Note that CoAP error responses derived from CoAP processing (point 10. in {{ver-req}}) are protected, as well as successful CoAP responses, while the OSCOAP errors (point 3., 4., 7. in {{ver-req}}) do not follow the processing below, but are sent as simple CoAP responses, without OSCOAP processing.

1. Retrieve the Sender Context in the Security Context used to verify the request.

2. Compose the Additional Authenticated Data, as described in {{cose-object}}.

3. Compute the AEAD nonce

   * If Observe is not used, compute the AEAD nonce by XORing the Common IV (with the most significant bit in the first byte flipped) with the padded Partial IV parameter from the request.
 
   * If Observe is used, compute the AEAD nonce by XORing the Common IV with the Partial IV of the response (Sender Sequence Number in network byte order). Then (in one atomic operation, see {{nonce-uniqueness}}) increment the Sender Sequence Number by one.

4. Encrypt the COSE object using the Sender Key. Compress the COSE Object as specified in {{compression}}.

5. Format the OSCOAP message according to {{protected-fields}}. The Object-Security option is added, see {{outer-options}}.

## Verifying the Response {#ver-res}

A client receiving a response containing the Object-Security option SHALL perform the following steps:

1. Process outer Block options according to {{RFC7959}}, until all blocks of the OSCOAP message have been received, see {{block-options}}.

2. Discard the message Code and all Outer options of Class non I and non U from the message. For example, ETag Outer option is discarded, Max-Age Outer option is not discarded.

3. Retrieve the Recipient Context associated with the Token. Decompress the COSE Object ({{compression}}). If either the decompression or the COSE message fails to decode, then go to 11.

4. For Observe notifications, verify the received 'Partial IV' parameter against the corresponding Notification Number as described in {{sequence-numbers}}. If the client receives a notification for which no Observe request was sent, then go to 11.

5. Compose the Additional Authenticated Data, as described in {{cose-object}}.

6. Compute the AEAD nonce

      * If the Observe option is not present in the response, compute the AEAD nonce by XORing the Common IV (with the most significant bit in the first byte flipped) with the padded Partial IV parameter from the request.
 
      * If the Observe option is present in the response, compute the AEAD nonce by XORing the Common IV with the padded Partial IV parameter from the response.

7. Decrypt the COSE object using the Recipient Key.

   * If decryption fails, then go to 11.

   * If decryption succeeds and Observe is used, update the corresponding Notification Number, as described in {{sequence-numbers}}.

8. For each decrypted option, check if the option is also present as an Outer option: if it is, discard the Outer. For example: the message contains a Max-Age Inner and a Max-Age Outer option. The Outer Max-Age is discarded.

9. Add decrypted code, options and payload to the decrypted request. The Object-Security option is removed.

   * If Observe is used, replace the Observe value with the 3 least significant bytes in the corresponding Notification Number.
   
10. The decrypted CoAP response is processed according to {{RFC7252}}

11. (Optional) In case any of the previous erroneous conditions apply: if the response is a CON message, then the client SHALL send an empty ACK back and stop processing the response; if the response is a NON message, then the client SHALL simply stop processing the response.

## Nonce generation examples {#nonce-generation}

This section illustrates the nonce generation in the different processing steps. Assume that:

* Endpoint A has the following security context parameters: Sender Key=K1, Sender IV=IV1, Sender Sequence Number=PIV1 and Recipient Key=K2, Recipient IV=IV2

* Endpoint B has the following security context parameters: Sender Key=K2, Sender IV=IV2, Sender Sequence Number=PIV2 and Recipient Key=K1, Recipient IV=IV1

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


Remarks:

* Note that endpoint A always uses key K1 for encrypting and K2 for verification, and vice versa for endpoint B. 

* All examples are individually based on the assumption on the endpoints stated above - the update of the security context parameters after each operation is omitted from these examples.



# OSCOAP Compression {#compression}

The Concise Binary Object Representation (CBOR) {{RFC7049}} combines very small message sizes with extensibility. The CBOR Object Signing and Encryption (COSE) {{RFC8152}} uses CBOR to create compact encoding of signed and encrypted data. COSE is however constructed to support a large number of different stateless use cases, and is not fully optimized for use as a stateful security protocol, leading to a larger than necessary message expansion. In this section, we define a simple stateless compression mechanism for OSCOAP, which significantly reduces the per-packet overhead.

## Encoding of the OSCOAP Payload

The payload of the OSCOAP message SHALL contain the compressed COSE object which is encoded as follows:

* The first byte (Flag Byte, see {{fig-flag-byte}}) encodes a set of flags and the length of the Partial IV parameter.
    - The three least significant bits encode the Partial IV length, n. If n = 0 then the Partial IV is not present in the compressed COSE object.
    - The fourth least significant bit is the kid flag, k: it is set to 1 if the kid is present in the compressed COSE object.
    - The fifth least significant bit is the auxiliary data flag, a: it is set to 1 if the compressed COSE object contains auxiliary data, see {{auxiliary-data}}.
    - The sixth-eighth least significant bits are reserved and SHALL be set to zero when not in use.
* The following n bytes encode the value of the Partial IV, if the Partial IV is present (n > 0).
* The following 1 byte encodes the length of the kid, m, if the kid flag is set (k = 1). 
* The following m bytes encode the value of the kid, if the kid flag is set (k = 1). 
* The following 1 byte encode the length of the auxiliary data, s, if the auxiliary data flag is set (a = 1).
* The following s bytes encode the auxiliary data, if the auxiliary data flag is set (a = 1).
* The remaining bytes encode the ciphertext.

~~~~~~~~~~~
 0 1 2 3 4 5 6 7 
+-+-+-+-+-+-+-+-+
|  Flag Byte    |                       
+-+-+-+-+-+-+-+-+
|  n  |k|a|0 0 0|    
+-+-+-+-+-+-+-+-+
n: Partial IV length (3 bits)
k: kid flag bit
a: auxiliary data flag bit
~~~~~~~~~~~
{: #fig-flag-byte title="Flag Byte for OSCOAP Compression" artwork-align="center"}

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
{: #fig-byte-flag title="Presence of data fields in compressed OSCOAP header" artwork-align="center"}

## Auxiliary Data  {#auxiliary-data}

For certain use cases, it is necessary or favorable for the sending endpoint to provide some auxiliary data in order for the receiving endpoint to retrieve the recipient context. One use case is if the same kid is used with multiple master keys, in which case some other identifier can be included as auxiliary data to enable the receiving endpoint to find the right security context. The auxiliary data is not protected, and so may be eavesdropped or manipulated in transfer. Applications need to make the appropriate security and privacy considerations of sending auxiliary data. 

Examples:

* If the sending endpoint has an identifier in some other namespace which can be used to retrieve or establish the security context, then that identifier can be used as auxiliary data.

* In case of a group communication scenario {{I-D.tiloca-core-multicast-oscoap}}, if the sender endpoint belongs to multiple groups involving the same endpoints, then a group identifier can be used as auxiliary data to enable the receiving endpoint to find the right group security context.


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

# Proxy Operations {#proxy-operations}

RFC7252 defines operations for a CoAP-to-CoAP proxy (see Section 5.7 of {{RFC7252}}) and for proxying between CoAP and HTTP (Section 10 of {{RFC7252}}). A more detailed description of the HTTP-to-CoAP mapping is provided by {{RFC8075}}.
This section describes the operations of OSCOAP-aware proxies.


## CoAP-to-CoAP Forwarding Proxy {#coap-coap-proxy}

OSCOAP is designed to work with legacy CoAP-to-CoAP forward proxies {{RFC7252}}, but OSCOAP-aware proxies provide certain simplifications as specified in this section. 

The targeted proxy operations are specified in Section 2.2.1 of {{I-D.hartke-core-e2e-security-reqs}}. In particular caching is disabled since the CoAP response is only applicable to the original client's CoAP request. A OSCOAP-aware proxy SHALL NOT cache a response to a request with an Object-Security option. As a consequence, the search for cache hits and CoAP freshness/Max-Age processing can be omitted. 

Proxy processing of the (Outer) Proxy-Uri option is as defined in {{RFC7252}}.

Proxy processing of the (Outer) Block options is as defined in {{RFC7959}} and {{I-D.amsuess-core-repeat-request-tag}}.

Proxy processing of the (Outer) Observe option is as defined in {{RFC7641}}. OSCOAP-aware proxies MAY look at the Partial IV value instead of the Outer Observe option.

## HTTP-to-CoAP Translation Proxy

As requested in Section 1 of {{RFC8075}}, this section describes the HTTP mapping for the OSCOAP protocol extension of CoAP.

The presence of the Object-Security option, both in requests and responses, is expressed in a HTTP header field named Object-Security in the mapped request or response. The value of the field is the compressed COSE Object of the OSCOAP message in base64url encoding without padding (see {{RFC7515}} Appendix C for implementation notes for this encoding).

Example:

~~~~~~~~~~~
[HTTP request -- Before object security processing]

  GET /hc/coap://device.local/orders HTTP/1.1
  Host: proxy.local

[HTTP request -- HTTP Client to Proxy]

  POST /hc/coap://device.local/ HTTP/1.1
  Host: proxy.local
  Object-Security: [empty]
  Body: 09 07 01 13 61 f7 0f d2 97 b1 [binary]
  
[CoAP request -- Proxy to CoAP Server]

  POST /
  Uri-Host: device.local
  Object-Security: [empty]
  Payload: 09 07 01 13 61 f7 0f d2 97 b1 [binary]

[CoAP response -- CoAP Server to Proxy]

  2.04 Changed
  Object-Security: [empty]
  Payload: 00 31 d1 fc f6 70 fb 0c 1d d5 ... [binary]

[HTTP response -- Proxy to HTTP Client]

  HTTP/1.1 200 OK
  Object-Security: [empty]
  Body: 00 31 d1 fc f6 70 fb 0c 1d d5 ... [binary]

[HTTP response -- After object security processing]

  HTTP/1.1 200 OK
  Body: Exterminate! Exterminate!
~~~~~~~~~~~

Note that the HTTP Status Code 200 in the next-to-last message is the mapping of CoAP Code 2.04 (Changed), whereas the HTTP Status Code 200 in the last message is the mapping of the CoAP Code 2.05 (Content), encrypted within the compressed COSE object carried in the Body of the HTTP response.


## CoAP-to-HTTP Translation Proxy 




# Security Considerations {#sec-considerations}

In scenarios with intermediary nodes such as proxies or brokers, transport layer security such as DTLS only protects data hop-by-hop. As a consequence, the intermediary nodes can read and modify information. The trust model where all intermediate nodes are considered trustworthy is problematic, not only from a privacy perspective, but also from a security perspective, as the intermediaries are free to delete resources on sensors and falsify commands to actuators (such as "unlock door", "start fire alarm", "raise bridge"). Even in the rare cases, where all the owners of the intermediary nodes are fully trusted, attacks and data breaches make such an architecture brittle.

DTLS protects hop-by-hop the entire CoAP message, including header, options, and payload. OSCOAP protects end-to-end the payload, and all information in the options and header, that is not required for proxy operations (see {{protected-fields}}). DTLS and OSCOAP can be combined, thereby enabling end-to-end security of CoAP payload, in combination with hop-by-hop protection of the entire CoAP message, during transport between end-point and intermediary node. The CoAP message layer, however, cannot be protected end-to-end through intermediary devices since the parameters Type and Message ID, as well as Token and Token Length may be changed by a proxy.

The use of COSE to protect CoAP messages as specified in this document requires an established security context. The method to establish the security context described in {{context-derivation}} is based on a common shared secret material in client and server, which may be obtained e.g. by using the ACE framework {{I-D.ietf-ace-oauth-authz}}. An OSCOAP profile of ACE is described in {{I-D.seitz-ace-oscoap-profile}}.

The mandatory-to-implement AEAD algorithm AES-CCM-16-64-128 is selected for compatibility with CCM*.

Most AEAD algorithms require a unique nonce for each message, for which the sender sequence numbers in the COSE message field "Partial IV" is used. If the recipient accepts any sequence number larger than the one previously received, then the problem of sequence number synchronization is avoided. With reliable transport, it may be defined that only messages with sequence number which are equal to previous sequence number + 1 are accepted. The alternatives to sequence numbers have their issues: very constrained devices may not be able to support accurate time, or to generate and store large numbers of random nonces. The requirement to change key at counter wrap is a complication, but it also forces the user of this specification to think about implementing key renewal.

The maximum sender sequence number is dependent on the AEAD algorithm. The maximum sender sequence number SHALL be 2^(min(nonce length in bits, 56) - 1) - 1, or any algorithm specific lower limit. The "-1" in the exponent stems from the same partial IV and flipped bit of IV ({{cose-object}}) is used in request and response. The compression mechanism ({{compression}}) assumes that the partial IV is 56 bits or less (which is the reason for min(,) in the exponent).

The inner block options enable the sender to split large messages into OSCOAP-protected blocks such that the receiving node can verify blocks before having received the complete message. The outer block options allow for arbitrary proxy fragmentation operations that cannot be verified by the endpoints, but can by policy be restricted in size since the encrypted options allow for secure fragmentation of very large messages. A maximum message size (above which the sending endpoint fragments the message and the receiving endpoint discards the message, if complying to the policy) may be obtained as part of normal resource discovery.

Applications need to use a padding scheme if the content of a message can be determined solely from the length of the payload. As an example, the strings "YES" and "NO" even if encrypted can be distinguished from each other as there is no padding supplied by the current set of encryption algorithms. Some information can be determined even from looking at boundary conditions. An example of this would be returning an integer between 0 and 100 where lengths of 1, 2 and 3 will provide information about where in the range things are. Three different methods to deal with this are: 1) ensure that all messages are the same length. For example, using 0 and 1 instead of 'yes' and 'no'. 2) Use a character which is not part of the responses to pad to a fixed length. For example, pad with a space to three characters. 3) Use the PKCS #7 style padding scheme where m bytes are appended each having the value of m. For example, appending a 0 to "YES" and two 1's to "NO". This style of padding means that all values need to be padded.

# Privacy Considerations

Privacy threats executed through intermediate nodes are considerably reduced by means of OSCOAP. End-to-end integrity protection and encryption of CoAP payload and all options that are not used for proxy operations, provide mitigation against attacks on sensor and actuator communication, which may have a direct impact on the personal sphere.

The unprotected options ({{fig-option-protection}}) may reveal privacy sensitive information. In particular Uri-Host SHOULD NOT contain privacy sensitive information. 

CoAP headers sent in plaintext allow for example matching of CON and ACK (CoAP Message Identifier), matching of request and responses (Token) and traffic analysis.

Using the mechanisms described in {{context-state}} may reveal when a device goes through a reboot. This can be mitigated by the device storing the precise state of sender sequence number and replay window on a clean shutdown.

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

The HTTP header field Object-Security is added to the Message Headers registry:

~~~~~~~~~~~
+-------------------+----------+----------+-------------------+
| Header Field Name | Protocol | Status   | Reference         |
+-------------------+----------+----------+-------------------+
| Object-Security   | http     | standard | [[this document]] |
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
  |       |       |
  +------>|       |            Code: 0.02 (POST)
  | POST  |       |           Token: 0x8c
  |       |       | Object-Security: -
  |       |       |         Payload: [kid:5f, Partial IV:42,
  |       |       |                  {Code:0.01,
  |       |       |                   Uri-Path:"alarm_status"}]
  |       |       |
  |       +------>|            Code: 0.02 (POST)
  |       | POST  |           Token: 0x7b
  |       |       | Object-Security: -
  |       |       |         Payload: [kid:5f, Partial IV:42,
  |       |       |                  {Code:0.01,
  |       |       |                   Uri-Path:"alarm_status"}]
  |       |       |
  |       |<------+            Code: 2.04 (Changed)
  |       |  2.04 |           Token: 0x7b
  |       |       | Object-Security: -
  |       |       |         Payload: [{Code:2.05, "OFF"}]
  |       |       |
  |<------+       |            Code: 2.04 (Changed)
  |  2.04 |       |           Token: 0x8c
  |       |       | Object-Security: -
  |       |       |         Payload: [{Code:2.05, "OFF"}]
  |       |       |
~~~~~~~~~~~
{: #fig-alarm title="Secure Access to Sensor. Square brackets [ ... ] indicate a COSE object. Curly brackets { ... \} indicate encrypted data." artwork-align="center"}

The request/response Codes are encrypted by OSCOAP and only dummy Codes (POST/Changed) are visible in the header of the OSCOAP message. The option Uri-Path ("alarm_status") and payload ("OFF") are encrypted.

The COSE header of the request contains an identifier (5f), indicating which security context was used to protect the message and a Partial IV (42). 

The server verifies that the Partial IV has not been received before. The client verifies that the response is bound to the request.

## Secure Subscribe to Sensor

This example targets the scenario in Section 3.2 of {{I-D.hartke-core-e2e-security-reqs}} and illustrates a client requesting subscription to a blood sugar measurement resource (GET /glucose), first receiving the value 220 mg/dl and then a second value 180 mg/dl.

~~~~~~~~~~~
Client  Proxy  Server
  |       |       |
  +------>|       |            Code: 0.05 (FETCH)
  | FETCH |       |           Token: 0x83
  |       |       |         Observe: 0
  |       |       | Object-Security: -
  |       |       |         Payload: [kid:ca, Partial IV:15,
  |       |       |                  {Code:0.01,
  |       |       |                   Uri-Path:"glucose"}]
  |       |       |
  |       +------>|            Code: 0.05 (FETCH)
  |       | FETCH |           Token: 0xbe
  |       |       |         Observe: 0
  |       |       | Object-Security: -
  |       |       |         Payload: [kid:ca, Partial IV:15,
  |       |       |                  {Code:0.01,
  |       |       |                   Uri-Path:"glucose"}]
  |       |       |
  |       |<------+            Code: 2.05 (Content)
  |       |  2.05 |           Token: 0xbe
  |       |       |         Observe: 7
  |       |       | Object-Security: -
  |       |       |         Payload: [Partial IV:32,
  |       |       |                  {Code:2.05,   
  |       |       |                   Content-Format:0, "220"}]
  |       |       |
  |<------+       |            Code: 2.05 (Content)
  |  2.05 |       |           Token: 0x83
  |       |       |         Observe: 7
  |       |       | Object-Security: -
  |       |       |         Payload: [Partial IV:32,
  |       |       |                  {Code:2.05,   
  |       |       |                   Content-Format:0, "220"}]
 ...     ...     ...
  |       |       |
  |       |<------+            Code: 2.05 (Content)
  |       |  2.05 |           Token: 0xbe
  |       |       |         Observe: 8
  |       |       | Object-Security: -
  |       |       |         Payload: [Partial IV:36,
  |       |       |                  {Code:2.05,
  |       |       |                   Content-Format:0, "180"}]
  |       |       |
  |<------+       |            Code: 2.05 (Content)
  |  2.05 |       |           Token: 0x83
  |       |       |         Observe: 8
  |       |       | Object-Security: -
  |       |       |         Payload: [Partial IV:36,
  |       |       |                  {Code:2.05,
  |       |       |                   Content-Format:0, "180"}]
  |       |       |
~~~~~~~~~~~
{: #fig-blood-sugar title="Secure Subscribe to Sensor. Square brackets [ ... ] indicate a COSE object. Curly brackets { ... \} indicate encrypted data." artwork-align="center"}

The request/response Codes are encrypted by OSCOAP and only dummy Codes (FETCH/Content) are visible in the header of the OSCOAP message. The options Content-Format (0) and the payload ("220" and "180"), are encrypted.

The COSE header of the request contains an identifier (ca), indicating the security context used to protect the message and a Partial IV (15). The COSE headers of the responses contains Partial IVs (32 and 36).

The server verifies that the Partial IV has not been received before. The client verifies that the responses are bound to the request and that the Partial IVs are greater than any Partial IV previously received in a response bound to the request.

--- fluff
