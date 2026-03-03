import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/open_poc_api_seed_joern_tls.json"): Unit = {
  def esc(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  }

  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  def emit(label: String, file: String, line: Int, code: String): Unit = {
    val json = s"""{\"label\":\"${esc(label)}\",\"file\":\"${esc(file)}\",\"line\":$line,\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  cpg.call("setDefaultHostnameVerifier").l.foreach { c =>
    emit("hostname_verifier", c.file.name.l.headOption.getOrElse(""), c.lineNumber.getOrElse(0), c.code)
  }

  cpg.typeDecl.name("SSLTrustManager").l.foreach { t =>
    emit("trust_manager", t.file.name.l.headOption.getOrElse(""), t.lineNumber.getOrElse(0), t.code)
  }

  writer.println()
  writer.println("]")
  writer.close()
}
