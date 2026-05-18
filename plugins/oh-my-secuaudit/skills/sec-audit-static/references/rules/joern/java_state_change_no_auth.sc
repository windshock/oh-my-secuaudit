import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/joern_state_change_no_auth.json"): Unit = {
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  val suspicious = cpg.method
    .where(_.typeDecl.name(".*Controller"))
    .filter { m =>
      val names = m.parameter.name.l
      names.contains("cpcoId") && names.contains("couponNo")
    }
    .filter { m =>
      m.call.name("(?i).*auth.*|.*sign.*|.*nonce.*|.*timestamp.*|.*hmac.*").isEmpty
    }
    .l

  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  suspicious.foreach { m =>
    val file = m.file.name.headOption.getOrElse("")
    val line = m.lineNumber.getOrElse(0)
    val code = m.code
    val json = s"""{\"method\":\"${esc(m.name)}\",\"file\":\"${esc(file)}\",\"line\":$line,\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }
  writer.println()
  writer.println("]")
  writer.close()
}
