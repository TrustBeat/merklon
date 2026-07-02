// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import java.net.URI
import java.net.http.{HttpClient as JHttpClient, HttpRequest, HttpResponse}

/** Blocking HTTP client backed by java.net.http (JDK 11+). No framework dependencies. */
final class HttpLogClient(baseUrl: String) extends LogClient:

  private val http = JHttpClient.newHttpClient()

  def fetchCheckpoint(): String =
    get(s"$baseUrl/checkpoint")

  def fetchInclusionProof(leafIndex: Long, treeSize: Long): String =
    get(s"$baseUrl/proof/inclusion?leaf_index=$leafIndex&tree_size=$treeSize")

  def fetchConsistencyProof(first: Long, second: Long): String =
    get(s"$baseUrl/proof/consistency?first=$first&second=$second")

  private def get(url: String): String =
    val req = HttpRequest.newBuilder(URI.create(url)).GET().build()
    val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
    if resp.statusCode() != 200
    then throw RuntimeException(s"HTTP ${resp.statusCode()} from $url: ${resp.body()}")
    else resp.body()
