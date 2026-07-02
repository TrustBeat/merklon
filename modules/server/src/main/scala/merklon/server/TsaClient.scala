// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.server

import merklon.{Checkpoint, MerkleTree, ProofBundleCodec}
import org.bouncycastle.tsp.{TimeStampRequestGenerator, TimeStampResponse, TSPAlgorithms}

import java.math.BigInteger
import java.net.URI
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}
import java.security.SecureRandom
import java.time.Duration

/** RFC 3161 client for one time-stamping authority (Bouncy Castle for the DER protocol, JDK HTTP
  * for transport). `tokenFor` caches the token per checkpoint: every bundle exported against the
  * same checkpoint reuses one TSA round-trip.
  */
final class TsaClient(baseUrl: String):

  private val http = JHttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
  private val random = SecureRandom()
  private var cached: Option[(String, Array[Byte])] = None // (size/rootHex, token DER)

  /** A timestamp token over `cp`'s note-body imprint (SPEC.md §8), cached per checkpoint. */
  def tokenFor(cp: Checkpoint): Either[String, Array[Byte]] = synchronized {
    val key = s"${cp.treeSize}/${MerkleTree.toHex(cp.rootHash)}"
    cached match
      case Some((k, token)) if k == key => Right(token)
      case _ =>
        timestamp(ProofBundleCodec.timestampImprint(cp)).map { token =>
          cached = Some((key, token))
          token
        }
  }

  /** One RFC 3161 round-trip: request a token over the SHA-256 `imprint`, validate the response
    * against the request (status, nonce, imprint echo), return the token DER.
    */
  def timestamp(imprint: Array[Byte]): Either[String, Array[Byte]] =
    try
      val reqGen = TimeStampRequestGenerator()
      reqGen.setCertReq(true) // ask the TSA to embed its certificate in the token
      val tspReq = reqGen.generate(TSPAlgorithms.SHA256, imprint, BigInteger(64, random))
      val httpReq = HttpRequest
        .newBuilder(URI.create(baseUrl))
        .header("Content-Type", "application/timestamp-query")
        .timeout(Duration.ofSeconds(10))
        .POST(HttpRequest.BodyPublishers.ofByteArray(tspReq.getEncoded))
        .build()
      val resp = http.send(httpReq, HttpResponse.BodyHandlers.ofByteArray())
      if resp.statusCode() != 200 then Left(s"TSA $baseUrl: HTTP ${resp.statusCode()}")
      else
        val tspResp = TimeStampResponse(resp.body())
        tspResp.validate(tspReq) // throws if the response does not match the request
        Option(tspResp.getTimeStampToken) match
          case Some(token) => Right(token.getEncoded)
          case None =>
            Left(s"TSA $baseUrl: no token in response (status ${tspResp.getStatusString})")
    catch case e: Exception => Left(s"TSA $baseUrl: ${e.getMessage}")
