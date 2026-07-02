// Copyright 2026 Trustbeat s.r.o.
// SPDX-License-Identifier: Apache-2.0

package merklon

/** The `structured-event/v1` envelope (SPEC.md §9): a generic, flat event record that downstream
  * applications can standardize on without forking the core.
  *
  * `prevRef` optionally chains this event to an earlier leaf hash; `payload` is free-form.
  */
final case class StructuredEvent(
    actor: String,
    action: String,
    source: String,
    time: Long,
    prevRef: Option[Array[Byte]] = None,
    payload: Option[String] = None
)

/** Canonical encoding and strict parsing for `structured-event/v1`.
  *
  * The same event must produce the same leaf hash no matter which producer emitted it, so
  * [[canonical]] is deterministic: keys in lexicographic order, no whitespace, minimal escaping,
  * UTF-8. [[parse]] fails closed: unknown fields, duplicate keys, nested values, non-integer
  * numbers, or malformed escapes are errors, never silently normalized away.
  */
object StructuredEvent:

  private val Required = Set("actor", "action", "source", "time")
  private val Optional = Set("prev_ref", "payload")

  /** Canonical bytes: `{"action":…,"actor":…[,"payload":…][,"prev_ref":…],"source":…,"time":…}` —
    * keys in lexicographic order, absent optional fields omitted, compact, UTF-8.
    */
  def canonical(e: StructuredEvent): Array[Byte] =
    val sb = StringBuilder()
    sb.append("{\"action\":").append(quote(e.action))
    sb.append(",\"actor\":").append(quote(e.actor))
    e.payload.foreach(p => sb.append(",\"payload\":").append(quote(p)))
    e.prevRef.foreach(r => sb.append(",\"prev_ref\":\"").append(MerkleTree.toHex(r)).append('"'))
    sb.append(",\"source\":").append(quote(e.source))
    sb.append(",\"time\":").append(e.time)
    sb.append('}')
    sb.result().getBytes("UTF-8")

  /** Parse and validate one `structured-event/v1` JSON object (tolerant of whitespace and field
    * order, strict about everything else).
    */
  def parse(json: String): Either[String, StructuredEvent] =
    try
      val fields = Parser(json).parseObject()
      for
        _ <- fields.keySet.find(k => !Required(k) && !Optional(k)).toLeft(()).left.map { k =>
          s"unknown field '$k'"
        }
        _ <- Required.find(!fields.contains(_)).toLeft(()).left.map(k => s"missing field '$k'")
        actor <- str(fields, "actor")
        action <- str(fields, "action")
        source <- str(fields, "source")
        time <- fields("time") match
          case JNum(n) if n >= 0 => Right(n)
          case JNum(n)           => Left(s"'time' must be >= 0, was $n")
          case _                 => Left("'time' must be an integer")
        prevRef <- fields.get("prev_ref") match
          case None          => Right(None)
          case Some(JStr(s)) => hex(s).map(Some(_))
          case Some(_)       => Left("'prev_ref' must be a hex string")
        payload <- fields.get("payload") match
          case None          => Right(None)
          case Some(JStr(s)) => Right(Some(s))
          case Some(_)       => Left("'payload' must be a string")
      yield StructuredEvent(actor, action, source, time, prevRef, payload)
    catch case ParseFail(msg) => Left(msg)

  private def str(fields: Map[String, JValue], key: String): Either[String, String] =
    fields(key) match
      case JStr(s) => Right(s)
      case _       => Left(s"'$key' must be a string")

  private def hex(s: String): Either[String, Array[Byte]] =
    if s.isEmpty then Left("'prev_ref' must not be empty")
    else if s.length % 2 != 0 || !s.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
    then Left("'prev_ref' must be lowercase hex")
    else Right(java.util.HexFormat.of().parseHex(s))

  /** JSON string with the minimal, deterministic escape set: `\"`, `\\`, the two-character escapes
    * for \b \f \n \r \t, `\u00xx` (lowercase) for other control characters, everything else raw
    * UTF-8.
    */
  private def quote(s: String): String =
    val sb = StringBuilder().append('"')
    s.foreach {
      case '"'           => sb.append("\\\"")
      case '\\'          => sb.append("\\\\")
      case '\b'          => sb.append("\\b")
      case '\f'          => sb.append("\\f")
      case '\n'          => sb.append("\\n")
      case '\r'          => sb.append("\\r")
      case '\t'          => sb.append("\\t")
      case c if c < 0x20 => sb.append(f"\\u${c.toInt}%04x")
      case c             => sb.append(c)
    }
    sb.append('"').result()

  private sealed trait JValue
  private final case class JStr(s: String) extends JValue
  private final case class JNum(n: Long) extends JValue
  private final case class ParseFail(msg: String) extends RuntimeException(msg)

  /** Minimal strict parser for exactly one flat JSON object of string / integer values. Rejects
    * nesting, duplicate keys, fractions/exponents, and trailing content. No dependencies — same
    * philosophy as the fixed-schema proof parsers.
    */
  private final class Parser(s: String):
    private var i = 0

    def parseObject(): Map[String, JValue] =
      skipWs()
      expect('{')
      skipWs()
      val fields = scala.collection.mutable.LinkedHashMap.empty[String, JValue]
      if !eof && peek == '}' then i += 1
      else
        var done = false
        while !done do
          skipWs()
          val key = parseString()
          if fields.contains(key) then fail(s"duplicate field '$key'")
          skipWs()
          expect(':')
          skipWs()
          fields.put(key, parseValue())
          skipWs()
          expect0() match
            case ',' => ()
            case '}' => done = true
            case c   => fail(s"expected ',' or '}', found '$c'")
      skipWs()
      if !eof then fail("trailing content after the event object")
      fields.toMap

    private def parseValue(): JValue =
      if eof then fail("unexpected end of input")
      else if peek == '"' then JStr(parseString())
      else if peek == '-' || peek.isDigit then JNum(parseLong())
      else fail(s"expected a string or integer value, found '$peek' (nesting is not allowed)")

    private def parseString(): String =
      expect('"')
      val sb = StringBuilder()
      var closed = false
      while !closed do
        val c = expect0()
        if c == '"' then closed = true
        else if c == '\\' then
          expect0() match
            case '"'  => sb.append('"')
            case '\\' => sb.append('\\')
            case '/'  => sb.append('/')
            case 'b'  => sb.append('\b')
            case 'f'  => sb.append('\f')
            case 'n'  => sb.append('\n')
            case 'r'  => sb.append('\r')
            case 't'  => sb.append('\t')
            case 'u' =>
              val hex = (0 until 4).map(_ => expect0()).mkString
              val code =
                try Integer.parseInt(hex, 16)
                catch case _: NumberFormatException => fail(s"invalid \\u escape '\\u$hex'")
              sb.append(code.toChar)
            case e => fail(s"invalid escape '\\$e'")
        else if c < 0x20 then fail("unescaped control character in string")
        else sb.append(c)
      sb.result()

    private def parseLong(): Long =
      val start = i
      if !eof && peek == '-' then i += 1
      while !eof && peek.isDigit do i += 1
      val text = s.substring(start, i)
      if text.isEmpty || text == "-" then fail("invalid number")
      if !eof && (peek == '.' || peek == 'e' || peek == 'E') then
        fail("only integers are allowed (no fractions or exponents)")
      text.toLongOption.getOrElse(fail(s"integer out of range: $text"))

    private def eof: Boolean = i >= s.length
    private def peek: Char = s.charAt(i)
    private def expect0(): Char =
      if eof then fail("unexpected end of input")
      val c = s.charAt(i); i += 1; c
    private def expect(c: Char): Unit =
      val got = expect0()
      if got != c then fail(s"expected '$c', found '$got'")
    private def skipWs(): Unit =
      while !eof && (peek == ' ' || peek == '\t' || peek == '\n' || peek == '\r') do i += 1
    private def fail(msg: String): Nothing = throw ParseFail(s"$msg (offset $i)")
