# fwknop

Single Packet Authorization (SPA): a client sends one encrypted, authenticated UDP packet to ask a server to open firewall access that is otherwise closed.

## Language

### Packets

**SPA packet**:
The single UDP datagram a client sends to request access.
_Avoid_: knock packet, request packet

**SPA data**:
The payload of an SPA packet: the encrypted, base64-encoded string that travels on the wire.
_Avoid_: ciphertext, wire string, payload

**SPA message**:
The decrypted, decoded contents of SPA data: random value, username, timestamp, message type, an access message or server command, and optionally NAT access, server auth and client timeout.
_Avoid_: packet, SPA request; also C fwknop's use of "SPA message" for the access-message field alone

**Message type**:
Which of the seven kinds an SPA message is: command, access, NAT access, local NAT access, or the client-timeout variant of one of the last three.
_Avoid_: request type, packet type

**Knock**:
The act of sending one SPA packet to a server.
_Avoid_: ping, SPA request

### Integrity

**Message digest**:
A hash of an SPA message's encoded fields, appended before encryption so the server can tell the decrypted message is intact.
_Avoid_: digest (unqualified), checksum

**HMAC**:
A keyed hash over SPA data, appended after encryption so the server can tell the packet came from someone holding the HMAC key.
_Avoid_: digest, signature, MAC

**Replay digest**:
A hash of an SPA packet's SPA data that identifies the packet so a repeat can be recognised.
_Avoid_: digest (unqualified), fingerprint

**Replay cache**:
The server's set of replay digests from SPA packets it has recently decrypted; a packet whose replay digest is already in it is rejected.
_Avoid_: digest cache, digest store

**Key set**:
The encryption key, encryption mode and optional HMAC key and HMAC type that a client and an access stanza must share for a packet to be accepted.
_Avoid_: credentials, keys (when the modes are meant too)

### Addresses

**Allow IP**:
The IP address the client asks the server to open access for. It travels inside the SPA packet. `0.0.0.0` (or `::`) means "whatever the packet source is".
_Avoid_: source IP, source address

**Packet source**:
The address an SPA packet actually arrived from, as the server observes it.
_Avoid_: source IP, sender IP, remote address

**Source**:
The networks (a single IP, a list of IPs or CIDRs, or `ANY`) an access stanza applies to. A packet source must fall inside them for the stanza to be tried.
_Avoid_: source IP, allowed sources

### Requests

**Access spec**:
A protocol and port the client wants opened, written `proto/port` (for example `tcp/22`).
_Avoid_: access (unqualified), port spec, open port

**Access message**:
An allow IP paired with an access spec, written `allow_ip,proto/port` (for example `203.0.113.7,tcp/22`). It is what an access request carries.
_Avoid_: access (unqualified), message (unqualified)

**Server command**:
A shell command the client asks the server to run, carried by a command message in place of an access message.
_Avoid_: command message (that is the message type, not its payload), cmd

### Configuration

**Access stanza**:
One server-side rule: which source it applies to, the keys that must decrypt and authenticate the packet, and what access it may grant. The server tries access stanzas in order.
_Avoid_: stanza (unqualified), access rule, entry

**Rc stanza**:
A named client profile in the client's rc file, holding default settings for one destination. The profile named `default` applies underneath any other.
_Avoid_: stanza (unqualified), profile, named config

### Firewall

**Action**:
The shell command the server runs for one lifecycle step: validate, init, check, open, close or shutdown.
_Avoid_: hook, firewall command, template

**Action template**:
A file supplying the actions for one kind of firewall (iptables, nftables, pf and so on).
_Avoid_: firewall profile, backend, template (unqualified)

**Placeholder**:
A named hole in an action, such as the allow IP or port, that the server fills in from the SPA message before running it.
_Avoid_: template variable, field

**Rule**:
An opening the server made in the firewall for one allow IP and access spec, which it closes when the rule's timeout runs out.
_Avoid_: action rule, access rule, active rule

### Time limits

**Client timeout**:
How long the client asks for its rule to stay open, carried in the SPA message.
_Avoid_: fw timeout, firewall timeout

**Access timeout**:
How long an access stanza keeps a rule open when the client asks for no particular time.
_Avoid_: default timeout, rule timeout

**Max access timeout**:
The longest client timeout an access stanza honors; a longer request is cut down to it.
_Avoid_: timeout cap, max timeout

**Max packet age**:
How far an SPA message's timestamp may be from the server's clock, in either direction, for the packet to be accepted.
_Avoid_: packet timeout, freshness window
