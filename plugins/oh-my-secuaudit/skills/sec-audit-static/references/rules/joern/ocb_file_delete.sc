import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter

importCpg("/Users/1004276/Downloads/sec_audit_playbook/workspace/ocb-community-api/cpg.bin.zip")

val results = cpg.call.methodFullName("java.io.File.delete:.*").map(c => (c.code, c.lineNumber, c.file.name)).l
val out = new PrintWriter("/Users/1004276/Downloads/sec_audit_playbook/state/ocb/joern_file_delete_results.txt")
results.foreach(r => out.println(r))
out.close()
