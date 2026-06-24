package merklon

import java.security.MessageDigest

/** RFC 6962 Merkle hashing primitives — the verifiable-log core.
  *
  * Domain separation follows RFC 6962:
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

  /** RFC 6962 leaf hash: SHA-256(0x00 || data). */
  def leafHash(data: Array[Byte]): Array[Byte] =
    sha256(Array(0x00.toByte) ++ data)

  /** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
  def nodeHash(left: Array[Byte], right: Array[Byte]): Array[Byte] =
    sha256((Array(0x01.toByte) ++ left) ++ right)

  /** RFC 6962 Merkle Tree Hash (MTH) over an ordered list of entries.
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

  /** Lower-case hex encoding of a byte array. */
  def toHex(bytes: Array[Byte]): String =
    val sb = new StringBuilder(bytes.length * 2)
    bytes.foreach(b => sb.append(f"${b & 0xff}%02x"))
    sb.toString
