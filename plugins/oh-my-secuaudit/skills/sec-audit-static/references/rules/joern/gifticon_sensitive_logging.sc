import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.CpgLoader

val cpgFile = params.getOrElse("cpgFile", "")
val cpg = CpgLoader.load(cpgFile)

// Find logger info/debug/warn/error calls where arguments contain sensitive identifiers
val hits = cpg.call
  .methodFullName(".*(log|logger).*\\.(info|debug|warn|error)")
  .argument
  .code(".*(couponNo|cpcoId|cpcoProdId|st11OrdNo|trsNo).*")
  .dedup

hits.l
