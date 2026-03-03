import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/open_poc_api_seed_joern_log_params.json"): Unit = {
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

  cpg.call.name("getParameter").l.foreach { c =>
    emit("request_param", c.file.name.l.headOption.getOrElse(""), c.lineNumber.getOrElse(0), c.code)
  }

  cpg.call.name("getParameterNames").l.foreach { c =>
    emit("request_param_names", c.file.name.l.headOption.getOrElse(""), c.lineNumber.getOrElse(0), c.code)
  }

  writer.println()
  writer.println("]")
  writer.close()
}
