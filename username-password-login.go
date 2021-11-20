package logininator

import (
	"net/http"

	"github.com/app-nerds/kit/v6/identity"
	"github.com/app-nerds/nerdweb/v2"
	"github.com/sirupsen/logrus"
)

/*
UserNamePasswordRequest is a user name and password login request.
*/
type UserNamePasswordRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

type ValidateUserNamePasswordFunc func(loginRequest UserNamePasswordRequest) (bool, map[string]interface{}, error)

/*
NewUserNamePasswordConfig creates a configuration for validating user name and
password login handlers.
*/
func NewUserNamePasswordConfig(jwtConfig identity.JWTServiceConfig, logger *logrus.Entry) LoginHandlerConfig {
	return LoginHandlerConfig{
		AccessControlAllowOrigin:  "*",
		AccessControlAllowMethods: "POST, OPTIONS",
		AccessControlAllowHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
		JWTService:                identity.NewJWTService(jwtConfig),
		Logger:                    logger,
	}
}

/*
LoginHandlerUserNamePassword is a handler for a login that expects both a
user name and a password. These credentials are verified against a provided
function.
*/
func LoginHandlerUserNamePassword(config LoginHandlerConfig, credentialValidationFunc ValidateUserNamePasswordFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err            error
			token          string
			loginRequest   UserNamePasswordRequest
			additionalData map[string]interface{}
			ok             bool
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
		ok, additionalData, err = credentialValidationFunc(loginRequest)

		if err != nil {
			config.Logger.WithError(err).Error("error validating login credentials")

			nerdweb.WriteJSON(config.Logger, w, http.StatusInternalServerError, GenericError{
				Message: "Error validating login credentials",
			})

			return
		}

		if !ok {
			invalidCredentials(w, r, config)
			return
		}

		// Generate a JWT token
		config.AdditionalData = additionalData
		if token, err = createToken(w, r, config); err != nil {
			return
		}

		// Log that we have a login and return a token.
		logLogin(r, config)
		writeToken(w, config, token)
	}
}
