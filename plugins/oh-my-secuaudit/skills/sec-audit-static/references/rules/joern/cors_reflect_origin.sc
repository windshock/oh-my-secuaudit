import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

@main def run(out: String = "state/joern_cors_reflect_origin.json"): Unit = {
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
  val writer = new PrintWriter(out)
  writer.println("[")
  var first = true

  val hits = cpg.call.name("addAllowedOrigin").argument.code(".*getHeader\\(\\\"Origin\\\"\\).*" ).l
  hits.foreach { c =>
    val file = c.file.name.l.headOption.getOrElse("")
    val line = c.lineNumber.getOrElse(0)
    val code = c.code
    val json = s"""{\"file\":\"${esc(file)}\",\"line\":${line},\"code\":\"${esc(code)}\"}"""
    if (!first) writer.println(",")
    writer.print(json)
    first = false
  }

  writer.println()
  writer.println("]")
  writer.close()
}
