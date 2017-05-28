/**
  * Created by MKucijan on 21.5.2017..
  */
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.core.util.IMap
import org.argus.jawa.core.Global


trait ApiMisuseChecker {
  def name: String
  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult
}

case class ApiMisuseResult(checkerName: String, misusedApis: IMap[(String, String), String]) {
  override def toString: String = {
    val sb = new StringBuilder
    sb.append(checkerName + ":\n")
    if(misusedApis.isEmpty) sb.append("  No misuse.\n")
    misusedApis.foreach {
      case ((sig, line), des) => sb.append("  " + sig + " " + line + " : " + des + "\n")
    }
    sb.toString().intern()
  }
}