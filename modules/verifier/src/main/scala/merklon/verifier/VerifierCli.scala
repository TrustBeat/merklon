// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon.verifier

import merklon.{Checkpoint, TrustedWitness, WitnessPolicy}
import java.util.HexFormat

/** Standalone CLI verifier. Fetches from a running merklon server and verifies locally.
  *
  * Usage: merklon-verify --url URL --pubkey HEX_PUBKEY [witness flags] COMMAND [ARGS]
  *
  * Commands:
  *   - checkpoint verify the latest checkpoint signature
  *   - inclusion LEAF_INDEX DATA_HEX verify that hex-encoded data is at the given leaf index
  *   - consistency OLD_SIZE OLD_ROOT_HEX verify the latest checkpoint is an append-only extension
  *     of a previously trusted (size, root) — i.e. the log has not rewritten history
  *
  * Witness policy (applies to every command when present):
  *   - `--witness NAME=HEX_PUBKEY` (repeatable) — a trusted witness
  *   - `--witness-threshold N` — require N distinct valid cosignatures (default: all listed
  *     witnesses)
  */
@main def merklon_verify(rawArgs: String*): Unit =
  val argv = rawArgs.toArray

  def flagValue(name: String): Option[String] =
    val i = argv.indexWhere(_ == name)
    if i >= 0 && i + 1 < argv.length then Some(argv(i + 1)) else None

  def flagValues(name: String): List[String] =
    argv.toList.zipWithIndex.collect {
      case (arg, i) if arg == name && i + 1 < argv.length => argv(i + 1)
    }

  val url = flagValue("--url").getOrElse { die("--url <base-url> is required") }
  val pubHex = flagValue("--pubkey").getOrElse { die("--pubkey <hex> is required") }
  val rawPub =
    try HexFormat.of().parseHex(pubHex)
    catch case _: Exception => die(s"--pubkey must be hex-encoded: $pubHex")

  val witnesses = flagValues("--witness").map { spec =>
    val eq = spec.lastIndexOf('=')
    if eq <= 0 then die(s"--witness must be NAME=HEX_PUBKEY: $spec")
    val name = spec.take(eq)
    val key =
      try HexFormat.of().parseHex(spec.drop(eq + 1))
      catch case _: Exception => die(s"--witness key must be hex-encoded: $spec")
    TrustedWitness(name, key)
  }
  val threshold = flagValue("--witness-threshold") match
    case Some(s) =>
      s.toIntOption.filter(_ >= 0).getOrElse(die(s"--witness-threshold must be a number: $s"))
    case None => witnesses.size // default: require all listed witnesses
  if threshold > witnesses.size then
    die(s"--witness-threshold $threshold exceeds the ${witnesses.size} listed witnesses")
  val policy = WitnessRequirement(witnesses, threshold)

  // Collect positional args: skip flags and their values.
  val flagsWithValues = Set("--url", "--pubkey", "--witness", "--witness-threshold")
  val positional = argv.toList.zipWithIndex
    .filterNot { (arg, i) =>
      arg.startsWith("--") || (i > 0 && flagsWithValues.contains(argv(i - 1)))
    }
    .map(_._1)

  val client = HttpLogClient(url)

  positional match
    case "checkpoint" :: _ =>
      runCheckpoint(client, rawPub, policy)

    case "inclusion" :: idxStr :: dataHex :: _ =>
      val idx = idxStr.toLongOption.getOrElse(die(s"leaf index must be a number: $idxStr"))
      val data =
        try HexFormat.of().parseHex(dataHex)
        catch case _: Exception => die(s"data must be hex-encoded: $dataHex")
      runInclusion(client, rawPub, policy, idx, data)

    case "consistency" :: oldSizeStr :: oldRootHex :: _ =>
      val oldSize =
        oldSizeStr.toLongOption.getOrElse(die(s"old size must be a number: $oldSizeStr"))
      val oldRoot =
        try HexFormat.of().parseHex(oldRootHex)
        catch case _: Exception => die(s"old root must be hex-encoded: $oldRootHex")
      runConsistency(client, rawPub, policy, oldSize, oldRoot)

    case other =>
      val cmd = other.headOption.getOrElse("(none)")
      die(
        s"unknown command: $cmd\n" +
          "usage: merklon-verify --url URL --pubkey HEX " +
          "[--witness NAME=HEX]... [--witness-threshold N] " +
          "checkpoint | inclusion INDEX DATA_HEX | consistency OLD_SIZE OLD_ROOT_HEX"
      )

/** The client-side N-of-M witness policy selected on the command line. */
private final case class WitnessRequirement(trusted: List[TrustedWitness], threshold: Int):
  /** Enforce the policy on `cp`, dying with a FAIL message if unmet. No-op without witnesses. */
  def enforce(cp: Checkpoint): Unit =
    if trusted.nonEmpty then
      val cosigners = WitnessPolicy.validCosigners(cp, trusted)
      if cosigners.size >= threshold then
        println(
          s"OK  witness policy: ${cosigners.size}/${trusted.size} valid cosignatures" +
            s" (threshold $threshold): ${cosigners.toList.sorted.mkString(", ")}"
        )
      else
        die(
          s"FAIL  witness policy: ${cosigners.size} valid cosignature(s), need $threshold" +
            (if cosigners.nonEmpty then s" (have: ${cosigners.toList.sorted.mkString(", ")})"
             else "")
        )

private def runCheckpoint(
    client: LogClient,
    rawPub: Array[Byte],
    policy: WitnessRequirement
): Unit =
  val text =
    try client.fetchCheckpoint()
    catch case e: Exception => die(s"fetch failed: ${e.getMessage}")
  val cp = CheckpointParser.parse(text).fold(e => die(s"checkpoint parse error: $e"), identity)
  if LogVerifier.verifyCheckpointSignature(cp, rawPub) then
    policy.enforce(cp)
    println(s"OK  checkpoint tree_size=${cp.treeSize} signature valid")
  else die("FAIL  checkpoint signature did not verify")

private def runInclusion(
    client: LogClient,
    rawPub: Array[Byte],
    policy: WitnessRequirement,
    leafIndex: Long,
    data: Array[Byte]
): Unit =
  val cpText =
    try client.fetchCheckpoint()
    catch case e: Exception => die(s"fetch failed: ${e.getMessage}")
  val cp = CheckpointParser.parse(cpText).fold(e => die(s"checkpoint parse error: $e"), identity)
  if !LogVerifier.verifyCheckpointSignature(cp, rawPub) then
    die("FAIL  checkpoint signature did not verify")
  policy.enforce(cp)
  val proofJson =
    try client.fetchInclusionProof(leafIndex, cp.treeSize)
    catch case e: Exception => die(s"fetch failed: ${e.getMessage}")
  val proof =
    ProofParser.parseInclusion(proofJson).fold(e => die(s"proof parse error: $e"), identity)
  if LogVerifier.verifyInclusion(data, proof, cp) then
    println(s"OK  leaf $leafIndex included in tree_size=${cp.treeSize}")
  else die(s"FAIL  inclusion proof for leaf $leafIndex did not verify")

private def runConsistency(
    client: LogClient,
    rawPub: Array[Byte],
    policy: WitnessRequirement,
    oldSize: Long,
    oldRoot: Array[Byte]
): Unit =
  val cpText =
    try client.fetchCheckpoint()
    catch case e: Exception => die(s"fetch failed: ${e.getMessage}")
  val newer = CheckpointParser.parse(cpText).fold(e => die(s"checkpoint parse error: $e"), identity)
  if !LogVerifier.verifyCheckpointSignature(newer, rawPub) then
    die("FAIL  checkpoint signature did not verify")
  policy.enforce(newer)
  if oldSize > newer.treeSize then
    die(s"FAIL  old size $oldSize is larger than current tree_size ${newer.treeSize}")
  val proofJson =
    try client.fetchConsistencyProof(oldSize, newer.treeSize)
    catch case e: Exception => die(s"fetch failed: ${e.getMessage}")
  val proof =
    ProofParser.parseConsistency(proofJson).fold(e => die(s"proof parse error: $e"), identity)
  // The older checkpoint is reconstructed from the operator-supplied trusted (size, root);
  // verifyConsistency only needs its size and root, not its signatures.
  val older = Checkpoint(newer.origin, oldSize, oldRoot, 0L, Vector.empty)
  if LogVerifier.verifyConsistency(older, newer, proof) then
    println(
      s"OK  tree_size=$oldSize is an append-only prefix of tree_size=${newer.treeSize}"
    )
  else die(s"FAIL  consistency proof $oldSize -> ${newer.treeSize} did not verify")

private def die(msg: String): Nothing =
  System.err.println(msg)
  sys.exit(1)
