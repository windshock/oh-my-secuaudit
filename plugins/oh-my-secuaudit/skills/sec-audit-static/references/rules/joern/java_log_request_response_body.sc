import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/joern_log_request_response_body.json"): Unit = {
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  val calls = cpg.call.code(".*Request Body.*|.*Response body.*").l

  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true
  calls.foreach { c =>
    val file = c.file.name.headOption.getOrElse("")
    val line = c.lineNumber.getOrElse(0)
    val code = c.code
    val json = s"""{\"file\":\"${esc(file)}\",\"line\":$line,\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }
  writer.println()
  writer.println("]")
  writer.close()
}
