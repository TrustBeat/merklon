// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.{Files, Path}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPair, KeyPairGenerator, Signature as JSignature}
import java.util.Base64

/** Loads (or creates) the operator's persisted Ed25519 log key.
  *
  * The key lives in a directory as two PEM files, both openssl-compatible:
  *   - `log.key` — PKCS#8 private key (`openssl pkey -in log.key`), mode 0600 where supported
  *   - `log.pub` — X.509 SubjectPublicKeyInfo public key
  *
  * Two files because the JDK offers no API to derive an Ed25519 public key from a private key, and
  * we never hand-roll curve arithmetic. On load the pair is checked with a sign/verify round trip
  * so a mismatched or corrupted pair fails at startup, not at first verification.
  */
object LogKeyStore:

  private val PrivateFile = "log.key"
  private val PublicFile = "log.pub"

  /** Load the key pair from `dir`, generating and persisting a fresh one if absent. */
  def loadOrCreate(dir: Path): KeyPair =
    val priv = dir.resolve(PrivateFile)
    val pub = dir.resolve(PublicFile)
    if Files.exists(priv) || Files.exists(pub) then load(priv, pub)
    else create(dir, priv, pub)

  private def load(priv: Path, pub: Path): KeyPair =
    require(Files.exists(priv), s"$priv missing (found ${pub.getFileName} without it)")
    require(Files.exists(pub), s"$pub missing (found ${priv.getFileName} without it)")
    val kf = KeyFactory.getInstance("Ed25519")
    val privateKey = kf.generatePrivate(
      new PKCS8EncodedKeySpec(readPem(priv, "PRIVATE KEY"))
    )
    val publicKey = kf.generatePublic(
      new X509EncodedKeySpec(readPem(pub, "PUBLIC KEY"))
    )
    val pair = new KeyPair(publicKey, privateKey)
    require(pairMatches(pair), s"$priv and $pub are not a matching Ed25519 key pair")
    pair

  private def create(dir: Path, priv: Path, pub: Path): KeyPair =
    Files.createDirectories(dir)
    val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    writePem(priv, "PRIVATE KEY", pair.getPrivate.getEncoded, restrict = true)
    writePem(pub, "PUBLIC KEY", pair.getPublic.getEncoded, restrict = false)
    pair

  /** Sign/verify round trip — proves the private and public halves belong together. */
  private def pairMatches(pair: KeyPair): Boolean =
    val probe = "merklon-key-pair-check".getBytes("UTF-8")
    val signer = JSignature.getInstance("Ed25519")
    signer.initSign(pair.getPrivate)
    signer.update(probe)
    val sig = signer.sign()
    val verifier = JSignature.getInstance("Ed25519")
    verifier.initVerify(pair.getPublic)
    verifier.update(probe)
    verifier.verify(sig)

  private def readPem(path: Path, label: String): Array[Byte] =
    val text = Files.readString(path)
    val begin = s"-----BEGIN $label-----"
    val end = s"-----END $label-----"
    val start = text.indexOf(begin)
    val stop = text.indexOf(end)
    require(start >= 0 && stop > start, s"$path is not a PEM '$label' file")
    val b64 = text.substring(start + begin.length, stop).filterNot(_.isWhitespace)
    Base64.getDecoder.decode(b64)

  private def writePem(path: Path, label: String, der: Array[Byte], restrict: Boolean): Unit =
    val b64 = Base64.getEncoder.encodeToString(der).grouped(64).mkString("\n")
    Files.writeString(path, s"-----BEGIN $label-----\n$b64\n-----END $label-----\n")
    if restrict then
      try Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
      catch case _: UnsupportedOperationException => () // non-POSIX FS (e.g. Windows)
