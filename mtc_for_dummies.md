# MTC (Merkle Tree COSE) for Dummies by a Bigger Dummy

## 1. The Problem Statement: Why We Can't Have Nice (Small) Things Anymore

*(Note: When I first started this proposal for CTAP and WebAuthn, **MTC** stood for "Merkle Tree Certificates." However, given that there is no asymmetric signature or certificate in the conventional sense, I am now retronyming it to **Merkle Tree COSE**, as it is based on COSE structures. Clever, no?)*

A typical X.509 certificate, at its core, ties a number of claims together in a way that can be verified. Typically, that verification is done through a series of asymmetric signatures that chain back to a known trust anchor or root that is self-signed. Each of the signed objects allows the parent or signer to make additional claims—or "constraints," in X.509 speak.

Here is the problem: **Post-Quantum Signatures** (another misnomer; they aren't *post-quantum*, only *resistant to post-quantum attacks*, but marketing got there before me) are **big** compared to elliptic curve keys and signatures. *(Call out to Canada's BlackBerry/Certicom for the last 20 years of tiny signatures!)*

Big keys and signatures mean we can't just toss them on the wire like we have gotten used to with ES256 without blowing up things like NFC that are designed for the current small data sizes. When I say "big," think **orders of magnitude larger**—for details, see my [other papers with the numbers](./pq_mtc_attestation_proposal.html) and the [6-level MTC Cryptographic Trust Chain & Signed Preimage Reference](./mtc_trust_chain_architecture.html). Just take my word for it for now.

So, what do we actually use attestations for, and how can we make them PQ-resistant to something like NIST's Level 5?

Currently, we have batch attestation. If the spec supports **ML-DSA-87** (NIST Level 5) attestation over an ML-DSA-87 public key, look at what we are actually shoving into the `MakeCredential` response:
1. A **big** credential public key (`ML-DSA-87`),
2. `authData` and `credentialId`,
3. A **big** `ML-DSA-87` attestation signature,
4. *Another* **big** `ML-DSA-87` public key (the batch key), wrapped in X.509 ASN.1 overhead, and
5. *Yet another* **big** `ML-DSA-87` signature by the parent (intermediate or root CA)!

That is **two signatures and two public keys** to prove that the new credential public key comes from an authenticator that is legitimately part of a batch (at least 100,000 authenticators) that are identified in the FIDO MDS with a set of properties indexed by that AAGUID.

Can we do better? You probably guessed that I think the answer is **yes**; otherwise, this document is likely a bait-and-switch to trick you into purchasing a timeshare, or to get you to purchase tokens if I have been replaced by Skynet.

---

## 2. On to Solutioneering: Taking the [Chainsaw](https://www.facebook.com/AlisonBraunPhotography/posts/doa-the-time-joey-shithead-brought-a-working-chainsaw-on-stage-april-1989-and-i-/1408436129869327/) to `MakeCredential`

The first thing is to strip out all the things we don't need:

1. **The Credential Public Key and `credentialId` (Keep):** We can't get rid of the credential public key and `credentialId`. At this point, the authenticator is the only one that knows them, and the whole purpose of `MakeCredential` is to get them to the RP so they can be used by the user to authenticate later. So we need to keep them.
2. **The `authData` (Keep):** We also need to keep the `authData`; it has the `rpIdHash`, `AAGUID`, counter, and other flags about `UP`, `UV`, and `BE` relevant to the `MakeCredential` registration.
3. **The Tricky `clientDataHash` (Keep Integrity-Protected):** The batch attestation signs over it, but it is not in the CTAP response directly, because the unhashed `clientData` is returned to the RP by the WebAuthn client. The information in `clientData` is important as it contains the challenge, Web origin, and other security-related gunk from the browser. We already save space on the wire by not returning it, but need to keep it integrity-protected in any new response.

### So What Do We Have Left?

The **X.509 certificate** is the only thing we have remaining to work with.

The certificate contains:
* The **batch public key** (**big**),
* The **AAGUID** (**small**),
* A **device serial number** if it is an enterprise attestation certificate,
* Some other stuff like the name of the manufacturer, the certificate expiry, and things that are generally ignored in practice, and
* Finally, the certificate is also signed by its **parent** (**big**).

For those following closely, you will have noticed that the **AAGUID is sent twice**. That is not large, but a definite candidate for trimming.

### Reconstructing the Pre-Image via the FIDO MDS

Anything that both the authenticator and the RP know (via MDS) can, like the `clientData`, be integrity-protected without being sent on the wire if we have a rule to reconstruct the pre-image for a signature/integrity protection.

So, to look things up in the MDS, we do need the AAGUID as that is the master index. However, we really only need it once if it is integrity-protected. The one in `authData` is signed over by the batch key, so if the batch key is protected, then we are good with just sending it there.

The next candidate is the big signature in the X.509 cert. It binds the AAGUID and the batch key together, but we already have an AAGUID signed over by the batch key.

Hmm... if we have to look the AAGUID up in the MDS to validate the parent of the X.509 cert and the other metadata anyway to trust the `MakeCredential` result, then if the MDS had the batch public key in the AAGUID entry, we would have both sides knowing the same info and we could drop it from the wire!

Now you are probably thinking: *if I trust the MDS to look this shit up in, then why do I need to send the signature on the wire for a trust chain that I, as an RP, can get from the MDS by looking up the AAGUID along with a small key identifier to find all of that in the MDS?*

So if we follow this to its logical conclusion—where we have the batch key signing over `authData` (which includes `credentialId` and the credential public key) plus `clientDataHash`—the RP now knows enough after looking up the AAGUID in the MDS to be able to reconstruct and validate the signature in the `MakeCredential` response **without sending anything from the X.509 certificate**.

To make it more efficient, we should send an index to identify the trust information for the batch public key. A given AAGUID in the MDS has roughly one batch key per 100,000 devices using that AAGUID. So there may be more than one batch key; best not to be ambiguous and force the RP to try all of them.

---

## 3. Wait... Why Did You Mention Merkle Trees Then? (Dedicated to Karen)

So far, we have cut out almost 2/3 of the response, and I have not mentioned Merkle once. At this point, Dirk is thinking: *"Why did you confuse people by dragging in crypto that wasn't needed? Keep it simple!"*

Well... I am not done yet.

We have the problem of not blowing up the size of the MDS, given that its current architecture is a monolithic signed blob of JSON. *(OK, so I can't really credibly complain about JOSE, but it is big, and we will eventually have to break it up in the same way that we had to for SAML metadata once the size of the files started blowing up XML parsers.)*

If we were only talking about batch certificates over 100,000 keys, we could just move the batch certificate from the key to the MDS and call it good. One big certificate per batch key won't kill anyone in the short term.

However, we also have the crowd favourite: **Enterprise Attestation**. Those authenticators contain a second certificate with a **batch size of 1** and a serial number (see CTAP/WebAuthn for details).

That is *way* more batch keys, and stuffing individual PQ public keys for every single device into the MDS shortens the time before we need to make major architectural changes to the MDS—probably making Karen sad, or worse, mad at me. **So I dedicate the Merkle part to her.**

### The Trusty Thing Formerly Known as a Certificate

Remember back at the start I talked about MTC certificates? These are going to be all over the internet for TLS because they are small (see [this article from Cloudflare on bootstrapping MTCs](https://blog.cloudflare.com/bootstrap-mtc/)).

There are a bunch of math things that make them similar to what we need, but not a drop-in replacement because TLS is interactive and we only have 1 request/response to work with. *(Ask me about sibling paths and inclusion proofs sometime when you want to be put to sleep.)*

So we determined that the **trusty thing formerly known as a certificate** can live in the MDS. If we have the trusty thing in the MDS and want to make it small, we can use the same techniques as X.509 MTC for TLS, but drop the ASN.1 encoding and other cruft to have a direct **CBOR representation** that fits with the rest of the protocol.

We continue to use `COSE_Key` to represent the public key *(there is a security reason for that—ask another time)*. And we can put all the required information for append-only Merkle trees in the MDS as JSON members.

### Roots, Checkpoints, and Leaves

Each batch key maps to one entry via its index in the tree. Each tree has one **root** and **0 to many checkpoints**. From a math perspective, they are sort of the same thing, but it is easier to differentiate them when talking about the lifetime.

The short version is that the **root** of the tree is normally pictured at the top, which can confuse people. The top is the hash of the concatenation of the two nodes below it, plus some other stuff you want to bind to it—like expiry, as an example.

The bits at the bottom are called **leaves**. I did not make this up. They are basically the hash of the claims you want to make—in our case, that the `COSE_Key`-encapsulated public key `X` belongs to AAGUID `Y` according to its manufacturer via a transitive trust chain going to some well-known root. 

*(OK, for the pedantic readers: you will have figured out that if the trusted root is in the MDS and not provided out-of-band, then the MDS is the root of trust, and we could have ended the validation several steps earlier. Let's just pretend some RPs get root certificates out-of-band for the keys because they don't trust the MDS 100%; I could say who they are, but I don't want to spend my next vacation at a black site.)*

Quickly moving on. If we start with a two-level tree that has one root and two leaves, that works OK if you only have two batches. Any reasonable person would make a bigger tree and plan ahead. All the AAGUIDs are the same; you just need to make some key pairs to fill the tree, keep them in your pocket, and publish them incrementally in the MDS as required. If you start off with a 5-level tree, you get 16 leaves. That is probably enough for most AAGUIDs.

You are starting to see a base-2 pattern here *(see first joke)*.

---

## 4. Saving Product Managers From Themselves: Append-Only Trees & Checkpoints

OK, so if you have a product manager incapable of planning ahead *(you know who you are)*, we do have a way to save your ass.

Remember I called them **append-only trees**. Pay close attention, as we are now getting towards the cool math stuff, and we have probably lost half the people who started reading this document at this point. Their loss—they are not cool like you, remaining reader.

The thing is that you can't add levels *below* the leaves, because those leaf values are hashes of the actual data we are asserting.

We *can*, however, add leaves to the bottom on the **right**. So if we start with a depth-2 tree, it has four leaves *(math nerds in graph theory count the connections between nodes to confuse regular people)*. Then, to append to it, we need to double the size by adding another 4 leaves to the right and nodes all the way up to make a new root at the top—and we call this new node a **checkpoint**.

### Before: Depth 2 Tree ($2^2 = 4$ Leaves)
```text
               [ Original Root ]             <-- Depth 0 (Root)
                 /           \                 (1st connection)
           [Node 0-1]     [Node 2-3]         <-- Depth 1 (Intermediate Nodes)
            /      \       /      \            (2nd connection)
         [L0]     [L1]   [L2]     [L3]       <-- Depth 2 (4 Leaves: Batch Keys 0..3)
```

### After: Appending to Make a Depth 3 Tree ($2^3 = 8$ Leaves)
```text
                             [ NEW CHECKPOINT ]                  <-- Depth 0 (New Top / Checkpoint)
                             /                \                    (1st connection)
                            /                  \
              [ Original Root ]              [New Node 4-7]      <-- Depth 1
                /           \                 /          \         (2nd connection)
          [Node 0-1]     [Node 2-3]     [Node 4-5]    [Node 6-7] <-- Depth 2
           /      \       /      \       /      \      /      \    (3rd connection)
        [L0]     [L1]   [L2]     [L3]  [L4]    [L5]  [L6]    [L7]<-- Depth 3 (8 Leaves: 0..3 + New 4..7)
        \___________  ______________/  \___________  ___________/
                    \/                             \/
           Original 4 Leaves             Appended 4 Leaves on Right
```

### Immutable Leaf Addresses & Checkpoint Bridging

The leaves are indexed from left to right, so their "address" never changes even when you add a new level.

The original tree still validates against the old root without updating any information that enterprise customers received in their manifests. The next cool math trick is that if we include the value of the new `Node 4-7` in the metadata of the checkpoint, all the old leaves (`L0`..`L3`) can now *also* validate against the new checkpoint simply by taking the `Original Root` and hashing it with the concatenated value of `Node 4-7`.

We can now keep the paths for existing nodes immutable in the enterprise manifest while being able to double the size of the tree as many times as we need to allow for as many enterprise keys as needed—just by adding levels and making checkpoints.

I can just feel the excitement.

---

## 5. ["Where's the Revocation?!"](https://www.youtube.com/watch?v=Ug75diEyiA0) & Conclusion

### ["Where's the Revocation?!"](https://www.youtube.com/watch?v=Ug75diEyiA0)

Now I can hear the remaining reader channeling that [classic 1984 fast-food commercial (*"Where's the beef?!"*)](https://www.youtube.com/watch?v=Ug75diEyiA0) and saying: *"All well and good, but where's the revocation?! I had totally unworkable, unscalable Certificate Revocation Lists (CRLs) with my X.509 certificates!"*

Well, remaining reader, if one Merkle is good, then two are better. I introduce you to **Sparse Merkle Trees** for proof of non-membership in a list of revoked credentials (see [Revocation in zkID: Merkle-Tree-Based Approaches](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)).

We can incorporate a check for people like you who are emotionally attached to revocation. Only the nodes that are revoked are included, so the proof is small and fast to check.

### In Conclusion

* **Most RPs** don't care about attestation and should be asking for [attestation type `none`](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion). This is the smallest response and gives the best performance on the wire.
* **RPs that want a traditional bloated certificate chain** can get that by asking for attestation type `packed`. That works OK over USB in environments where you know the HID stack has been updated to support the larger size.
* **RPs that *do* care about authenticator provenance** and are doing it through random end-user systems—banks perhaps being a good example of this—can use the new **`mtc` attestation type** and get the best performance possible. Older platforms won't send the attestation type in CTAP 2.1 requests, causing authenticators to fall back to whatever they have as a default, perhaps batching with the smaller ES256 signature to be backwards compatible.

Finally, the good news is that **authenticators don't need to choose**. They can use the same batch keys for both `packed` and `mtc` attestation types, and the additional `mtc` storage requirements are super small.

So this is what I wish I could've explained to Dirk on the first go-round.

Send questions, and I will try to clarify and update this as I get feedback.

*All names used in this document are fictional, and any resemblance to persons living or dead is purely coincidental.*
