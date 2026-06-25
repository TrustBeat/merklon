// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

import java.security.MessageDigest
import java.util.Arrays

/** RFC 9162 (Certificate Transparency 2.0, obsoletes RFC 6962) Merkle hashing primitives — the
  * verifiable-log core. The Merkle tree, hashing, and proof definitions are unchanged from RFC
  * 6962, so the RFC 6962 reference test vectors remain valid.
  *
  * Domain separation follows RFC 9162 §2.1.1:
  *   - leaf hash: SHA-256(0x00 || data)
  *   - node hash: SHA-256(0x01 || left || right)
  *   - Merkle Tree Hash of the empty list: SHA-256() (the hash of the empty string)
  *
  * This object is intentionally pure and dependency-light. Inclusion and consistency proofs build
  * on these primitives in Phase 0.
  */
object MerkleTree:

  private def sha256(bytes: Array[Byte]): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(bytes)

  /** RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || data). */
  def leafHash(data: Array[Byte]): Array[Byte] =
    sha256(Array(0x00.toByte) ++ data)

  /** RFC 9162 §2.1.1 interior node hash: SHA-256(0x01 || left || right). */
  def nodeHash(left: Array[Byte], right: Array[Byte]): Array[Byte] =
    sha256((Array(0x01.toByte) ++ left) ++ right)

  /** RFC 9162 §2.1.1 Merkle Tree Hash (MTH) over an ordered list of entries.
    *
    * MTH({}) = SHA-256() MTH({d0}) = leafHash(d0) MTH(D[n]) = nodeHash(MTH(D[0:k]), MTH(D[k:n]))
    * where k is the largest power of two strictly less than n.
    */
  def root(entries: List[Array[Byte]]): Array[Byte] =
    entries match
      case Nil           => sha256(Array.emptyByteArray)
      case single :: Nil => leafHash(single)
      case _ =>
        val n = entries.length
        val k = Integer.highestOneBit(n - 1) // largest power of two < n
        val (l, r) = entries.splitAt(k)
        nodeHash(root(l), root(r))

  // ---------------------------------------------------------------------------
  // Inclusion proofs (RFC 9162 §2.1.3 — the audit path)
  // ---------------------------------------------------------------------------

  /** Build the inclusion (audit) proof for the leaf at `index` in the tree over `entries`.
    *
    * RFC 9162 §2.1.3.1 PATH(m, D[n]):
    *   - PATH(0, D[1]) = {}
    *   - PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) if m < k
    *   - PATH(m, D[n]) = PATH(m-k, D[k:n]) : MTH(D[0:k]) if m >= k
    * where k is the largest power of two strictly less than n.
    *
    * The returned path is ordered bottom-up: the sibling closest to the leaf comes first.
    */
  def inclusionProof(index: Int, entries: List[Array[Byte]]): List[Array[Byte]] =
    val n = entries.length
    require(index >= 0 && index < n, s"index $index out of range for tree of size $n")
    if n == 1 then Nil
    else
      val k = Integer.highestOneBit(n - 1)
      val (l, r) = entries.splitAt(k)
      if index < k then inclusionProof(index, l) :+ root(r)
      else inclusionProof(index - k, r) :+ root(l)

  /** Verify an inclusion proof without trusting the prover (RFC 9162 §2.1.3.2).
    *
    * Recomputes the root from `leafHash` and the sibling `proof`, and checks it equals
    * `expectedRoot`. Pure: no tree, no server state — exactly what an independent verifier runs.
    */
  def verifyInclusion(
      leafIndex: Int,
      treeSize: Int,
      leafHash: Array[Byte],
      proof: List[Array[Byte]],
      expectedRoot: Array[Byte]
  ): Boolean =
    if leafIndex < 0 || leafIndex >= treeSize then false
    else
      var fn = leafIndex
      var sn = treeSize - 1
      var r = leafHash
      var ok = true
      val it = proof.iterator
      while ok && it.hasNext do
        val p = it.next()
        if sn == 0 then ok = false
        else
          if (fn & 1) == 1 || fn == sn then
            r = nodeHash(p, r)
            // ascend past trailing zero bits of fn (a left-edge node has no left sibling here)
            while (fn & 1) == 0 && fn != 0 do
              fn >>= 1
              sn >>= 1
          else r = nodeHash(r, p)
          fn >>= 1
          sn >>= 1
      ok && sn == 0 && Arrays.equals(r, expectedRoot)

  // ---------------------------------------------------------------------------
  // Consistency proofs (RFC 9162 §2.1.4 — append-only / no history rewrite)
  // ---------------------------------------------------------------------------

  /** Build the consistency proof that the size-`first` tree is a prefix of the tree over `entries`
    * (whose size is the "second" size).
    *
    * RFC 9162 §2.1.4.1 PROOF(m, D[n]) = SUBPROOF(m, D[n], true), with SUBPROOF(m, D[m], true) = {}
    * SUBPROOF(m, D[m], false) = {MTH(D[m])} SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) :
    * MTH(D[k:n]) if m <= k SUBPROOF(m, D[n], b) = SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k]) if m >
    * k
    */
  def consistencyProof(first: Int, entries: List[Array[Byte]]): List[Array[Byte]] =
    val n = entries.length
    require(first >= 0 && first <= n, s"first $first out of range for tree of size $n")
    if first == 0 || first == n then Nil
    else subProof(first, entries, b = true)

  private def subProof(m: Int, entries: List[Array[Byte]], b: Boolean): List[Array[Byte]] =
    val n = entries.length
    if m == n then if b then Nil else List(root(entries))
    else
      val k = Integer.highestOneBit(n - 1)
      val (l, r) = entries.splitAt(k)
      if m <= k then subProof(m, l, b) :+ root(r)
      else subProof(m - k, r, b = false) :+ root(l)

  /** Verify a consistency proof without trusting the prover (RFC 9162 §2.1.4.2).
    *
    * Confirms that a log of size `first` with root `firstRoot` is an append-only prefix of a log of
    * size `second` with root `secondRoot`. This is the property that makes the log tamper-evident:
    * a server cannot rewrite history without producing an invalid consistency proof.
    */
  def verifyConsistency(
      first: Int,
      second: Int,
      firstRoot: Array[Byte],
      secondRoot: Array[Byte],
      proof: List[Array[Byte]]
  ): Boolean =
    if first < 0 || first > second then false
    else if first == second then proof.isEmpty && Arrays.equals(firstRoot, secondRoot)
    else if first == 0 then proof.isEmpty // empty tree is a prefix of every tree
    else
      // If `first` is an exact power of two, firstRoot is an implied node not carried in the
      // proof; seed it back in (RFC 9162 §2.1.4.2 step 1).
      val path = if (first & (first - 1)) == 0 then firstRoot :: proof else proof
      if path.isEmpty then false
      else
        var fn = first - 1
        var sn = second - 1
        while (fn & 1) == 1 do
          fn >>= 1
          sn >>= 1
        var fr = path.head
        var sr = path.head
        var ok = true
        val it = path.iterator.drop(1)
        while ok && it.hasNext do
          val c = it.next()
          if sn == 0 then ok = false
          else
            if (fn & 1) == 1 || fn == sn then
              fr = nodeHash(c, fr)
              sr = nodeHash(c, sr)
              while (fn & 1) == 0 && fn != 0 do
                fn >>= 1
                sn >>= 1
            else sr = nodeHash(sr, c)
            fn >>= 1
            sn >>= 1
        ok && sn == 0 && Arrays.equals(fr, firstRoot) && Arrays.equals(sr, secondRoot)

  /** Lower-case hex encoding of a byte array. */
  def toHex(bytes: Array[Byte]): String =
    val sb = new StringBuilder(bytes.length * 2)
    bytes.foreach(b => sb.append(f"${b & 0xff}%02x"))
    sb.toString
