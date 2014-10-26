package spray.routing.authentication

import scala.concurrent.{ ExecutionContext, Future }
import spray.routing.{ RequestContext, Session, Rejection }
import com.typesafe.config.{ Config, ConfigFactory }
import spray.util.SettingsCompanion
import akka.actor.ActorRefFactory
import spray.util.actorSystem

case class SessionAuthenticatorSettings(userKey: Option[String])
object SessionAuthenticatorSettings extends SettingsCompanion[SessionAuthenticatorSettings]("spray.session") {
  def fromSubConfig(c: Config) = apply(readValue(c getString "auth-key"))

  implicit def default(implicit refFactory: ActorRefFactory) = apply(actorSystem)
}

/**
 * An SessionAuthenticator is a UserSessionAuthenticator that uses a given session passed to the server from the client
 * to authenticate the user and extract a user object.
 */
class SessionAuthenticator[U](findUser: String ⇒ Option[U])(implicit val executionContext: ExecutionContext) extends UserSessionAuthenticator[U] {

  val sessionAuthenticatorSettings = SessionAuthenticatorSettings(ConfigFactory.load())
  val userKey: String = sessionAuthenticatorSettings.userKey.getOrElse("SPRAY-USER")

  def apply(session: Option[Session]): Future[Authentication[Option[U]]] = {
    Future.successful {
      Right(session.flatMap(_.get(userKey)).flatMap {
        findUser(_)
      })
    }
  }

}

object SessionLoginAuth {

  def apply[T](findUser: String ⇒ Option[T])(implicit ec: ExecutionContext) = new SessionAuthenticator[T](findUser)

}