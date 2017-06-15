/**
  * Created by MKucijan on 21.5.2017..
  */
import java.util.NoSuchElementException

import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.plugin.apiMisuse.CryptographicConstants
import org.argus.jawa.alir.controlFlowGraph.{ICFGCallNode, ICFGNode}
import org.argus.jawa.alir.dataFlowAnalysis.InterproceduralDataFlowGraph
import org.argus.jawa.alir.pta.suspark.InterproceduralSuperSpark
import org.argus.jawa.alir.pta.{Instance, PTAConcreteStringInstance, PTAResult, VarSlot}
import org.argus.jawa.alir.util.ExplicitValueFinder
import org.argus.jawa.compiler.parser.{AssignmentStatement, CallStatement, NameExpression}
import org.argus.jawa.core._
import org.argus.jawa.core.util.{ISet, _}
import org.argus.jawa.alir.Context


class ExtCryptographicMisuse extends ApiMisuseChecker {
  val name = "CryptographicMisuse"

  var idfg:Option[InterproceduralDataFlowGraph] = None
  var apk:Option[Global] = None

  def check(global: Global,idfgOpt: Option[InterproceduralDataFlowGraph]): ApiMisuseResult = {

        val misusedApis: MMap[(String, String), String] = mmapEmpty
        global.getApplicationClasses foreach {
          clazz =>
          //val clazz = global.getClassOrResolve(comp._1)
          val idfg = InterproceduralSuperSpark(global, clazz.getDeclaredMethods.map(_.getSignature))
          this.idfg = Some(idfg)
          this.apk = Some(global)
          val icfg = idfg.icfg
          val ptaresult = idfg.ptaresult

          val nodeMap: MMap[String, MSet[ICFGCallNode]] = mmapEmpty

          icfg.nodes.foreach {
            node =>
              val result = getCryptoNode(global, node)
              result.foreach {
                r =>
                  nodeMap.getOrElseUpdate(r._1, msetEmpty) += r._2
              }
          }

          val rule1Res = ECBCheck(global, nodeMap, ptaresult)
          rule1Res.foreach {
            case (n, b) =>
              if (!b) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = "Using ECB mode!"
              }
          }
          val rule2Res = IVCheck(global, nodeMap, ptaresult)
          rule2Res.foreach {
            case (n, r) =>
              if (r.isDefined) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = r.get
              }
          }

          val rule3Res = KeyCheck(global, nodeMap, ptaresult)
          rule3Res.foreach {
            case (n, r) =>
              if (r.isDefined) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = r.get
              }
          }

          val rule4Res = PBEKeySpecSaltCheck(global, nodeMap, ptaresult)
          rule4Res.foreach {
            case (n, r) =>
              if (r.isDefined) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = r.get
              }
          }

          val rule5Res = PBEKeySpecIterCheck(global, nodeMap, ptaresult)
          rule5Res.foreach {
            case (n, r) =>
              if (r.isDefined) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) += r.get
              }
          }

          val rule6Res = SecureRandomCheck(global, nodeMap, ptaresult)
          rule6Res.foreach {
            case (n, r) =>
              if (r.isDefined) {
                misusedApis((n.getContext.getMethodSig.signature, n.getContext.getCurrentLocUri)) = r.get
              }
          }
        }
        ApiMisuseResult(name, misusedApis.toMap)
    }


  def getCryptoNode(global: Global, node: ICFGNode): Set[(String, ICFGCallNode)] = {
    val result: MSet[(String, ICFGCallNode)] = msetEmpty
    node match{
      case invNode: ICFGCallNode =>
        val calleeSet = invNode.getCalleeSet
        calleeSet.foreach{
          callee =>
            val calleep = callee.callee
            val callees: MSet[Signature] = msetEmpty
            callees += calleep
            callees.foreach{
              callee =>
                if(CryptographicConstants.getCryptoAPIs.contains(callee.signature) || CryptographicConstantsExtended.getCryptoAPIs.contains(callee.signature)){
                  result += ((callee.signature, invNode))
                }
            }
        }
      case _ =>
    }
    result.toSet
  }


  def retrive_string_arguments(value: Instance,k: Int,depth: Int):MMap[Context, MSet[String]] = {
    if (depth>=10)
      return mmapEmpty

    val (sig, str) = value.defSite.getContext.head

    val argMap: MMap[Context, MSet[String]] = mmapEmpty
    idfg.get.icfg.nodes foreach {
      case cn: ICFGCallNode if ((cn.getCalleeSig == sig) && cn.argNames.size>k) =>

        val baseSlot = VarSlot(cn.argNames.head, isBase = false, isArg = true)
        val bases = idfg.get.ptaresult.pointsToSet(baseSlot, cn.getContext)
        val strSlot = VarSlot(cn.argNames(k), isBase = false, isArg = true)
        val values = idfg.get.ptaresult.pointsToSet(strSlot, cn.getContext) map {
          case pcsi: PTAConcreteStringInstance => pcsi.string
          case an => "ANY"
        }

        val m= apk.get.getMethod(cn.getOwner).get
        var next_k = -1
        var i = 1
        m.params.foreach {
          f=>
            if(strSlot.varName==f._1)
              next_k=i
            i += 1
        }

        for (base <- bases;
             vl <- values) {
          if (base.isUnknown &&(next_k != -1))
            argMap ++= retrive_string_arguments(base,next_k,depth+1)
          argMap.getOrElseUpdate(base.defSite, msetEmpty) += vl
        }
      case _ =>
    }
    return argMap
  }
  /**
    * Rule 1 forbids the use of ECB mode because ECB mode is deterministic and not stateful,
    * thus cannot be IND-CPA secure.
    */
  def ECBCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Boolean] = {
    val result: MMap[ICFGCallNode, Boolean] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstants.getCipherGetinstanceAPIs.contains(sig))
          nodes ++= ns
    }
    nodes.foreach{
      node =>
        result += (node -> true)
        val m = global.getMethod(node.getOwner).get
        val loc = m.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
        require(argNames.isDefinedAt(0))
        val argSlot = VarSlot(argNames.head, isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)

        var k = -1
        var i = 1
        m.params.foreach {
          f=>
            if(argSlot.varName==f._1)
              k=i
            i += 1
        }

        val v_name=ExplicitValueFinder.findExplicitLiteralForArgs(m, loc, argNames(0)).filter(_.isString).map(_.getString)
        val argMap: MMap[Context, MSet[String]] = mmapEmpty
        if(v_name.isEmpty) {
          argValue foreach {
            case instance: PTAConcreteStringInstance =>
              if (CryptographicConstants.getECBSchemes.contains(instance.string))
                result += (node -> false)
            case value =>
              if (value.isUnknown && (k != -1))
                argMap ++= retrive_string_arguments(value, k,0)
          }
        } else {
          v_name.foreach { str =>
            if(CryptographicConstants.getECBSchemes.contains(str))
              result += (node -> false)
          }
        }
        argMap.foreach {
          f=>
            if(CryptographicConstants.getECBSchemes.contains(f._2.head))
              result += (node -> false)
        }
    }
    result.toMap
  }

  def retrive_arg_state(v: Instance,k : Int,depth : Int): Boolean = {

    if(depth>=10)
      return false
    val (sig, str) = v.defSite.getContext.head
    var flag_s=false


    idfg.get.icfg.nodes foreach {
      case cn: ICFGCallNode if ((cn.getCalleeSig == sig) && (cn.argNames.size>=k)) =>
        val argSlot = VarSlot(cn.argNames(k), isBase = false, isArg = true)
        val argValue = idfg.get.ptaresult.pointsToSet(argSlot, cn.context)


        val m= apk.get.getMethod(cn.getOwner).get
        val loc = m.getBody.resolvedBody.locations(cn.locIndex)
        flag_s=ExplicitValueFinder.isArgStaticBytes(m,loc,cn.argNames(k))

        var next_k = -1
        var i = 1

        m.params.foreach {
          f=>
            if(argSlot.varName==f._1)
              next_k=i
            i += 1
        }


        if((next_k != -1) && (flag_s == false)) {
          argValue.foreach {
            instance =>
              if(retrive_arg_state(instance,next_k,depth+1))
                return true
          }
        }
      case _ =>
    }
    return flag_s
  }

  /**
    * Rule 2 Do not use a non-random IV for CBC encryption.
    */
  def IVCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
    val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstants.getIVParameterInitAPIs.contains(sig))
          nodes ++= ns
    }
    nodes.foreach{
      node =>
        result += (node -> None)
        val m = global.getMethod(node.getOwner).get
        val loc = m.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
        require(argNames.isDefinedAt(0))
        val argSlot = VarSlot(argNames.head, isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)

        var flag_s=ExplicitValueFinder.isArgStaticBytes(m,loc,node.argNames(1))

        var k = -1
        var i = 1
        if(!argValue.isEmpty) {
          argValue.foreach {
            inst =>
              val inst_met= global.getMethod(inst.defSite.getMethodSig).get
              val method_type =inst_met.params.head._2
              if(inst_met == m) {
                val var_type = inst.typ
                if ((method_type.baseTyp <= var_type.baseTyp) && (var_type.dimensions == method_type.dimensions))
                  k = i
              }
              i=i+1
          }
        }

        if((k != -1) && (flag_s == false)) {
          if(argValue.head.isUnknown)
            flag_s = retrive_arg_state(argValue.head, k,0)
        }

        if(flag_s)
          result += (node -> Some("non-random IV!"))
    }
    result.toMap
  }

  def KeyCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
    val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstantsExtended.getKeyParametarInitAPIs.contains(sig)) {
          nodes ++= ns
        }
    }
    nodes.foreach{
      node =>
        result += (node -> None)
        val m=global.getMethod(node.getOwner).get
        val loc = m.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
        require(argNames.isDefinedAt(0))
        val argSlot = VarSlot(argNames(0), isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)

        var flag_s=ExplicitValueFinder.isArgStaticBytes(m,loc,node.argNames(1))

        var k = -1
        var i = 1
        if(!argValue.isEmpty) {
          argValue.foreach {
            inst =>
              val inst_met= global.getMethod(inst.defSite.getMethodSig).get
              inst_met.params.foreach {
                f =>
                  val method_type = f._2
                    if (inst_met == m) {
                      val var_type = inst.typ
                      if ((method_type.baseTyp <= var_type.baseTyp) && (var_type.dimensions == method_type.dimensions))
                        k = i
                    }
                  i = i + 1
              }
          }
        }

        if((k != -1) && (flag_s == false)) {
          if(argValue.head.isUnknown)
            flag_s = retrive_arg_state(argValue.head, k,0)
        }

        if(flag_s)
          result += (node -> Some("Constant Key!"))
    }
    result.toMap
  }


def PBEKeySpecSaltCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
  val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
  val nodes: MSet[ICFGCallNode] = msetEmpty
  nodeMap.foreach{
    case (sig, ns) =>
      if(CryptographicConstantsExtended.getPBEKeySpecAPIs.contains(sig)) {
        nodes ++= ns
      }
  }
  nodes.foreach{
    case node if (node.argNames.size>=3) =>
      result += (node -> None)
      val m=global.getMethod(node.getOwner).get
      val loc = m.getBody.resolvedBody.locations(node.locIndex)
      val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
      require(argNames.isDefinedAt(1))
      val argSlot = VarSlot(argNames(1), isBase = false, isArg = true)
      val argValue = ptaresult.pointsToSet(argSlot, node.context)

      var flag_s=ExplicitValueFinder.isArgStaticBytes(m,loc,node.argNames(2))

      var k = -1
      var i = 1
      if(!argValue.isEmpty) {
        argValue.foreach {
          inst =>
            val inst_met= global.getMethod(inst.defSite.getMethodSig).get
            inst_met.params.foreach {
              f =>
                val method_type = f._2
                if (inst_met == m) {
                  val var_type = inst.typ
                  if ((method_type.baseTyp <= var_type.baseTyp) && (var_type.dimensions == method_type.dimensions))
                    k = i
                }
                i = i + 1
            }
        }
      }

      if((k != -1) && (flag_s == false)) {
        if(argValue.head.isUnknown)
          flag_s = retrive_arg_state(argValue.head, k,0)
      }

      if(flag_s) {
        result += (node -> Some("Constant Salt for PBE!"))
      }
    case _ =>
    }
  result.toMap
  }


  def retrive_arg_int(v: Instance,k : Int,depth : Int): Set[Int] = {
    if(depth>=10)
      return Set[Int]()

    val (sig, str) = v.defSite.getContext.head


    var res = Set[Int]()
    idfg.get.icfg.nodes foreach {
      case cn: ICFGCallNode if ((cn.getCalleeSig == sig)&&(cn.argNames.size>k)) =>
        val argSlot = VarSlot(cn.argNames(k), isBase = false, isArg = true)
        val argValue = idfg.get.ptaresult.pointsToSet(argSlot, cn.context)


        val m= apk.get.getMethod(cn.getOwner).get
        val loc = m.getBody.resolvedBody.locations(cn.locIndex)
        val res=ExplicitValueFinder.findExplicitLiteralForArgs(m,loc,cn.argNames(k)).filter(_.isInt).map(_.getInt)

        var next_k = -1
        var i = 1

        m.params.foreach {
          f=>
            if(argSlot.varName==f._1)
              next_k=i
            i += 1
        }


        if((next_k != -1) && (res.isEmpty)) {
          argValue.foreach {
            instance =>
              return retrive_arg_int(instance,next_k,depth+1)
          }
        }
      case _ =>
    }
    return res
  }


  def PBEKeySpecIterCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
    val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstantsExtended.getPBEKeySpecAPIs.contains(sig)) {
          nodes ++= ns
        }
    }
    nodes.foreach{
      case node if node.argNames.size>=5=>
        result += (node -> None)
        val m=global.getMethod(node.getOwner).get
        val loc = m.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
        require(argNames.isDefinedAt(2))
        val argSlot = VarSlot(argNames(2), isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)

        var flag_s=ExplicitValueFinder.findExplicitLiteralForArgs(m,loc,node.argNames(3)).filter(_.isInt).map(_.getInt)

        var k = -1
        var i = 1
        if(!argValue.isEmpty) {
          argValue.foreach {
            inst =>
              val inst_met= global.getMethod(inst.defSite.getMethodSig).get
              inst_met.params.foreach {
                f =>
                  val method_type = f._2
                  if (inst_met == m) {
                    val var_type = inst.typ
                    if ((method_type.baseTyp <= var_type.baseTyp) && (var_type.dimensions == method_type.dimensions))
                      k = i
                  }
                  i = i + 1
              }
          }
        }

        if((k != -1) && (flag_s.isEmpty)) {
          if(argValue.head.isUnknown)
            flag_s = retrive_arg_int(argValue.head, k,0)
        }
        flag_s.foreach {
          num =>
            if(num<1000)
              result += (node -> Some(" Number of iteration lower then 1000."))
        }
    }
    result.toMap
  }



  def SecureRandomCheck(global: Global, nodeMap: MMap[String, MSet[ICFGCallNode]], ptaresult: PTAResult): IMap[ICFGCallNode, Option[String]] = {
    val result: MMap[ICFGCallNode, Option[String]] = mmapEmpty
    val nodes: MSet[ICFGCallNode] = msetEmpty
    nodeMap.foreach{
      case (sig, ns) =>
        if(CryptographicConstantsExtended.getSecureRandomApis.contains(sig)) {
          nodes ++= ns
        }
    }
    nodes.foreach{
      case node if (node.argNames.size==2) =>
        result += (node -> None)
        val m=global.getMethod(node.getOwner).get
        val loc = m.getBody.resolvedBody.locations(node.locIndex)
        val argNames: IList[String] = loc.statement.asInstanceOf[CallStatement].args
        val argSlot = VarSlot(argNames(0), isBase = false, isArg = true)
        val argValue = ptaresult.pointsToSet(argSlot, node.context)

        var flag_s=ExplicitValueFinder.isArgStaticBytes(m,loc,node.argNames(1))

        var k = -1
        var i = 1
        if(!argValue.isEmpty) {
          argValue.foreach {
            inst =>
              val inst_met= global.getMethod(inst.defSite.getMethodSig).get
              inst_met.params.foreach {
                f =>
                  val method_type = f._2
                  if (inst_met == m) {
                    val var_type = inst.typ
                    if ((method_type.baseTyp <= var_type.baseTyp) && (var_type.dimensions == method_type.dimensions))
                      k = i
                  }
                  i = i + 1
              }
          }
        }

        if((k != -1) && (flag_s == false)) {
          if(argValue.head.isUnknown)
            flag_s = retrive_arg_state(argValue.head, k,0)
        }

        if(flag_s)
          result += (node -> Some("Constant Secure Random seed!"))
      case _ =>
    }
    result.toMap
  }
}