/**
  * Created by MKucijan on 9.5.2017..
  */
object CryptographicConstantsExtended {

  def getCryptoAPIs: Set[String] = getKeyParametarInitAPIs ++ getPBEKeySpecAPIs ++ getSecureRandomApis

  /**
    *  Rule 3.
    */
  final val Cipher_init_API_1="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;)V"
  final val Cipher_init_API_2="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/AlgorithmParameters;)V"
  final val Cipher_init_API_3="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"
  final val Cipher_init_API_4="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;Ljava/security/SecureRandom;)V"
  final val Cipher_init_API_5="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/AlgorithmParameters;Ljava/security/SecureRandom;)V"
  final val Cipher_init_API_6="Ljavax/crypto/Cipher;.init:(ILjava/security/Key;Ljava/security/SecureRandom;)V"
  final val JAVAX_KEYPARAMETER_INIT_1 ="Ljavax/crypto/spec/SecretKeySpec;.<init>:([BLjava/lang/String;)V"
  final val JAVAX_KEYPARAMETER_INIT_2 ="Ljavax/crypto/spec/SecretKeySpec;.<init>:([BIILjava/lang/String;)V"


  def getCipher_InitApis: Set[String] = Set(Cipher_init_API_1,Cipher_init_API_2,Cipher_init_API_3,Cipher_init_API_4,Cipher_init_API_5,Cipher_init_API_6)
  def getKeyParametarInitAPIs: Set[String] = Set(JAVAX_KEYPARAMETER_INIT_1,JAVAX_KEYPARAMETER_INIT_2)

  /**
    * Rule 4. 5.
    */
  final val PBE_KEY_SPEC_1="Ljavax/crypto/spec/PBEKeySpec;.<init>:([C[BII)V"
  final val PBE_KEY_SPEC_2="Ljavax/crypto/spec/PBEKeySpec;.<init>:([C[BI)V"
  final val PBE_KEY_SPEC_3="Ljavax/crypto/spec/PBEKeySpec;.<init>:([C[B)V"
  final val PBE_KEY_SPEC_4="Ljavax/crypto/spec/PBEKeySpec;.<init>:([C)V"

  def getPBEKeySpecAPIs: Set[String] = Set(PBE_KEY_SPEC_1,PBE_KEY_SPEC_2,PBE_KEY_SPEC_3,PBE_KEY_SPEC_4)

  /**
    * Rule 6.
    */
  //final val SECURE_RANDOM_INIT_1="Ljava/security/SecureRandom;.<init>:()V"
  final val SECURE_RANDOM_INIT_2="Ljava/security/SecureRandom;.<init>:([B)V"

  def getSecureRandomApis: Set[String] = Set(SECURE_RANDOM_INIT_2)

}
