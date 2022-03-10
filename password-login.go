package logininator

import (
	"net/http"

	"github.com/ResurgenceIT/kit/v6/identity"
	"github.com/ResurgenceIT/nerdweb/v2"
	"github.com/sirupsen/logrus"
)

/*
PasswordLoginRequest is a password-only login request.
*/
type PasswordLoginRequest struct {
	Password string `json:"password"`
}

/*
NewPasswordOnlyConfig creates a configuration for a basic, password-only
login handler.
*/
func NewPasswordOnlyConfig(password string, jwtConfig identity.JWTServiceConfig, logger *logrus.Entry) LoginHandlerConfig {
	return LoginHandlerConfig{
		AccessControlAllowOrigin:  "*",
		AccessControlAllowMethods: "POST, OPTIONS",
		AccessControlAllowHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
		JWTService:                identity.NewJWTService(jwtConfig),
		Logger:                    logger,
		ServerPassword:            password,
	}
}

/*
LoginHandlerPassword is a handler for a login that only expects a
password. This password is verified against a password provided in
the LoginHandlerConfig.
*/
func LoginHandlerPassword(config LoginHandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err          error
			token        string
			loginRequest PasswordLoginRequest
		)

		setAccessHeaders(w, config)

		if r.Method == http.MethodOptions {
			return
		}

		// Read the body
		if err = nerdweb.ReadJSONBody(r, &loginRequest); err != nil {
			config.Logger.WithError(err).Error("invalid login request")

			nerdweb.WriteJSON(config.Logger, w, http.StatusBadRequest, GenericError{
				Message: "Invalid login request",
			})

			return
		}

		// Validate
		if loginRequest.Password != config.ServerPassword {
			invalidCredentials(w, r, config)
			return
		}

		// Generate a JWT token
		if token, err = createToken(w, r, config); err != nil {
			return
		}

		// Log that we have a login and return a token.
		logLogin(r, config)
		writeToken(w, config, token)
	}
}
