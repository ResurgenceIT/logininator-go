package logininator

import (
	"net/http"

	"github.com/app-nerds/kit/v6/identity"
	"github.com/app-nerds/nerdweb/v2"
	"github.com/sirupsen/logrus"
)

/*
UserNamePasswordCodeRequest is a user name and password + code login request.
*/
type UserNamePasswordCodeRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

type ValidateUserNamePasswordCodeFunc func(loginRequest UserNamePasswordCodeRequest) (bool, map[string]interface{}, error)

/*
NewUserNamePasswordCodeConfig creates a configuration for validating user name and
password + code login handlers.
*/
func NewUserNamePasswordCodeConfig(jwtConfig identity.JWTServiceConfig, logger *logrus.Entry) LoginHandlerConfig {
	return LoginHandlerConfig{
		AccessControlAllowOrigin:  "*",
		AccessControlAllowMethods: "POST, OPTIONS",
		AccessControlAllowHeaders: "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization",
		JWTService:                identity.NewJWTService(jwtConfig),
		Logger:                    logger,
	}
}

/*
LoginHandlerUserNamePasswordCode is a handler for a login that expects a
user name, password, and code. These credentials are verified against a provided
function.
*/
func LoginHandlerUserNamePasswordCode(config LoginHandlerConfig, credentialValidationFunc ValidateUserNamePasswordCodeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err            error
			token          string
			loginRequest   UserNamePasswordCodeRequest
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
