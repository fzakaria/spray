package spray.util

import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import com.typesafe.config.{ Config, ConfigFactory }
import akka.actor.ActorRefFactory

case class CryptoSettings(secretKey: Option[String])

object CryptoSettings extends SettingsCompanion[CryptoSettings]("spray.util") {
  def fromSubConfig(c: Config) = apply(readValue(c getString "secret-key"))

  implicit def default(implicit refFactory: ActorRefFactory) =
    apply(actorSystem)
}

trait Crypto {

  def sign(message: String, key: Array[Byte]): String

  def sign(message: String): String

}

object Crypto extends Crypto {

  private lazy val secret: String = CryptoSettings(ConfigFactory.load()).secretKey getOrElse "SECRET-KEY-PLEASE-CHANGE"

  def hex2bytes(hex: String): Array[Byte] = {
    hex.replaceAll("[^0-9A-Fa-f]", "").sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }

  def bytes2hex(bytes: Array[Byte], sep: Option[String] = None): String = {
    sep match {
      case None ⇒ bytes.map("%02x".format(_)).mkString
      case _    ⇒ bytes.map("%02x".format(_)).mkString(sep.get)
    }
  }

  override def sign(message: String, key: Array[Byte]): String = {
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(new SecretKeySpec(key, "HmacSHA1"))
    bytes2hex(mac.doFinal(message.getBytes("utf-8")))
  }

  override def sign(message: String): String = {
    sign(message, secret.getBytes("utf-8"))
  }

}