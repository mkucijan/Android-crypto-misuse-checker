/**
  * Created by MKucijan on 8.5.2017..
  */
import java.io.File

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.AndroidGlobalConfig
import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.core.util.IgnoreException
import org.argus.jawa.core._
import org.argus.jawa.core.util._

object ApiCryptoMisuse {
  def main(args: Array[String]): Unit = {
    if (args.length != 2) {
      println("usage: apk_path output_path")
      return
    }
    try {

      val debug = false
      val checker = new ExtCryptographicMisuse
      val fileUri = FileUtil.toUri(args(0))
      val outputUri = FileUtil.toUri(args(1))
      val reporter = new DefaultReporter
      val yard = new ApkYard(reporter)
      val layout = DecompileLayout(outputUri)
      val strategy = DecompileStrategy(new DefaultLibraryAPISummary(AndroidGlobalConfig.settings.third_party_lib_file),layout)
      val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
      val apk = yard.loadApk(fileUri, settings, collectInfo = true)


      val res = checker.check(apk,None);
      println(res)

      if (debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
    } catch {
      case _: IgnoreException => println("No interested api found.")
    }
  }


  def getOutputDirUri(outputUri: FileResourceUri, apkUri: FileResourceUri): FileResourceUri = {
    outputUri + {if(!outputUri.endsWith("/")) "/" else ""} + apkUri.substring(apkUri.lastIndexOf("/") + 1, apkUri.lastIndexOf("."))
  }

}
