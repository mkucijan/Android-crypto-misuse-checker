/**
  * Created by MKucijan on 9.5.2017..
  */

import org.argus.amandroid.plugin.apiMisuse.CryptographicConstants
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.compiler.parser.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.util._


//works only inside 1 function

class ExtendedCryptographicMisuse extends ApiMisuseChecker {

  val name = "CryptographicMisuse"

  def check(global: Global, idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {
    val misusedApis: MMap[(String, String), String] = mmapEmpty
    global.getApplicationClassCodes foreach { case (typ, f) =>
      if(f.code.contains("Ljavax/crypto/Cipher;.getInstance:(Ljava/lang/String;")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule1Res = ECBCheck(m)
              rule1Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use ECB mode!"
              }
            }
          case None =>
        }
      }
      if(f.code.contains("Ljavax/crypto/spec/IvParameterSpec;.<init>:([B")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule2Res = IVCheck(m)
              rule2Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use non-random IV!"
              }
            }
          case None =>
        }
      }

      if(f.code.contains("Ljavax/crypto/spec/SecretKeySpec;.<init>:([B")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule2Res = CipherKeyCheck(m)
              rule2Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use non-random keys."
              }
            }
          case None =>
        }
      }

      if(f.code.contains("Ljavax/crypto/spec/PBEKeySpec;.<init>:([C")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>

              val rule2Res = PBEKeySpecSaltCheck(m)
              rule2Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use constant salt for PBE"
              }

              val rule2Res2 = PBEKeySpecIterCheck(m)
              rule2Res2 foreach { uri =>
                if (rule2Res.contains(uri)) {
                  misusedApis((m.getSignature.signature, uri)) += " || Use less then 1000 iteration on PBE"
                } else {
                  misusedApis((m.getSignature.signature, uri)) = "Use less then 1000 iteration on PBE"
                }
              }

            }
          case None =>
        }
      }

      if(f.code.contains("Ljava/security/SecureRandom;.<init>:(")) {
        global.getClazz(typ) match {
          case Some(c) =>
            c.getDeclaredMethods.foreach { m =>
              val rule2Res = SecureRandomCheck(m)
              rule2Res foreach { uri =>
                misusedApis((m.getSignature.signature, uri)) = "Use non-random seed for SecureRandom!"
              }
            }
          case None =>
        }
      }
    }
    ApiMisuseResult(name, misusedApis.toMap)
  }

  /**
    * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful,
    * thus cannot be IND-CPA secure.
    */
  private def ECBCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations.foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstants.getCipherGetinstanceAPIs.contains(cs.signature.signature)) {
            val value = ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(0)).filter(_.isString).map(_.getString)
            value.foreach { str =>
              if(CryptographicConstants.getECBSchemes.contains(str)) result += l.locationUri
            }
          }
        case _=>
      }
    }
    result.toSet
  }

  /**
    * Rule 2 Do not use a non-random IV for CBC encryption.
    */
  private def IVCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstants.getIVParameterInitAPIs.contains(cs.signature.signature)) {
            if(ExplicitValueFinder.isArgStaticBytes(method, l, cs.arg(0))) {
              result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

  /**
    * Rule 3 Do not use constant encryption keys.
    */
  private def CipherKeyCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstantsExtended.getKeyParametarInitAPIs.contains(cs.signature.signature)) {
            if( ExplicitValueFinder.isArgStaticBytes(method, l, cs.arg(0))) {
              result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

  /**
    * Rule 4. Do not use constant salts for PBE
    */
  private def PBEKeySpecSaltCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstantsExtended.getPBEKeySpecAPIs.contains(cs.signature.signature)) {
            if( (cs.args.size==1) || (cs.args.size>=2 && ExplicitValueFinder.isArgStaticBytes(method, l, cs.arg(1))) ) {
              result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

  /**
    * Rule 5. use fewer then 1000 iterations.
    */
  private def PBEKeySpecIterCheck(method: JawaMethod): ISet[String] = {

    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstantsExtended.getPBEKeySpecAPIs.contains(cs.signature.signature)) {
            if (cs.args.size>=3)  {
              val value=ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(2)).filter(_.isInt).map(_.getInt)
              value foreach { num =>
                if (num < 1000)
                  result += l.locationUri
              }
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

  /**
    * Rule 6 Dont not use constant seed.
    */
  private def SecureRandomCheck(method: JawaMethod): ISet[String] = {
    val result: MSet[String] = msetEmpty
    method.getBody.resolvedBody.locations foreach { l =>
      l.statement match {
        case cs: CallStatement =>
          if(CryptographicConstantsExtended.getSecureRandomApis.contains(cs.signature.signature)) {
            if( (cs.args.size==1) && ExplicitValueFinder.isArgStaticBytes(method, l, cs.arg(0))) {
              result += l.locationUri
            }
          }
        case _ =>
      }
    }
    result.toSet
  }

}