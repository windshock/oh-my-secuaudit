import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/open_poc_api_gw_seed_joern_tls.json"): Unit = {
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  def emit(label: String, file: String, line: Int, code: String): Unit = {
    val json = s"""{\"label\":\"${esc(label)}\",\"file\":\"${esc(file)}\",\"line\":$line,\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  cpg.call.code(".*ALLOW_ALL_HOSTNAME_VERIFIER.*").l.foreach { c =>
    emit("allow_all_hostname_verifier", c.file.name.l.headOption.getOrElse(""), c.lineNumber.getOrElse(0), c.code)
  }

  cpg.call.code(".*setDefaultHostnameVerifier.*").l.foreach { c =>
    emit("set_default_hostname_verifier", c.file.name.l.headOption.getOrElse(""), c.lineNumber.getOrElse(0), c.code)
  }

  cpg.method.name("checkServerTrusted").l.foreach { m =>
    emit("check_server_trusted", m.file.name.l.headOption.getOrElse(""), m.lineNumber.getOrElse(0), m.code)
  }

  writer.println()
  writer.println("]")
  writer.close()
}
