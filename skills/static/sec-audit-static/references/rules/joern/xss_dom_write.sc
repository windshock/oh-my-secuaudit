import io.shiftleft.semanticcpg.language._

@main def xssDomWrite(): Unit = {
  val documentWrite = cpg.call.code(".*document\\.write\\(.*").l
  val innerHtmlAssign = cpg.assignment.code(".*innerHTML\\s*=.*").l
  val hits = (documentWrite ++ innerHtmlAssign).distinct
  println(s"hits: ${hits.size}")
  hits.take(10).foreach(n => println(n.code))
}
