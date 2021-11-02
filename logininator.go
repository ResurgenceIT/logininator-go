package logininator

import (
	"net/http"

	"github.com/app-nerds/kit/v6/identity"
	"github.com/app-nerds/nerdweb/v2"
	"github.com/sirupsen/logrus"
)

/*
GenericError is a generic error message.
*/
type GenericError struct {
	Message string `json:"message"`
}

/*
JWTLoginResponse provides the caller a JWT token upon
successful login.
*/
type JWTLoginResponse struct {
	Token string `json:"token"`
}

/*
LoginHandlerConfig is used to configure a login handler.
*/
type LoginHandlerConfig struct {
	AccessControlAllowOrigin  string
	AccessControlAllowMethods string
	AccessControlAllowHeaders string
	JWTService                identity.IJWTService
	Logger                    *logrus.Entry
	ServerPassword            string
	UserName                  string
	AdditionalData            map[string]interface{}
}

/*
PasswordLoginRequest is a password-only login request.
*/
type PasswordLoginRequest struct {
	Password string `json:"password"`
}

/*
UserNamePasswordRequest is a user name and password login request.
*/
type UserNamePasswordRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

type ValidateUserNamePasswordFunc func(loginRequest UserNamePasswordRequest) (bool, map[string]interface{}, error)

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

func setAccessHeaders(w http.ResponseWriter, config LoginHandlerConfig) {
	w.Header().Set("Access-Control-Allow-Origin", config.AccessControlAllowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", config.AccessControlAllowMethods)
	w.Header().Set("Access-Control-Allow-Headers", config.AccessControlAllowHeaders)
}

func invalidCredentials(w http.ResponseWriter, r *http.Request, config LoginHandlerConfig) {
	fields := logrus.Fields{
		"ip": nerdweb.RealIP(r),
	}

	if config.UserName != "" {
		fields["username"] = config.UserName
	}

	config.Logger.WithFields(fields).Error("invalid login attempt")

	nerdweb.WriteJSON(config.Logger, w, http.StatusUnauthorized, GenericError{
		Message: "Invalid user name/password",
	})
}

func createToken(w http.ResponseWriter, r *http.Request, config LoginHandlerConfig) (string, error) {
	var (
		err   error
		token string
	)

	createTokenRequest := identity.CreateTokenRequest{}

	if config.UserName != "" {
		createTokenRequest.UserName = config.UserName
	}

	if config.AdditionalData != nil {
		createTokenRequest.AdditionalData = config.AdditionalData
	}

	if token, err = config.JWTService.CreateToken(createTokenRequest); err != nil {
		config.Logger.WithError(err).WithFields(logrus.Fields{
			"ip": nerdweb.RealIP(r),
		}).Error("error creating JWT token during login")

		nerdweb.WriteJSON(config.Logger, w, http.StatusInternalServerError, GenericError{
			Message: "Error creating JWT token",
		})

		return token, err
	}

	return token, nil
}

func logLogin(r *http.Request, config LoginHandlerConfig) {
	fields := logrus.Fields{
		"ip": nerdweb.RealIP(r),
	}

	if config.UserName != "" {
		fields["username"] = config.UserName
	}

	config.Logger.WithFields(fields).Info("user logged in")
}

func writeToken(w http.ResponseWriter, config LoginHandlerConfig, token string) {
	result := JWTLoginResponse{
		Token: token,
	}

	nerdweb.WriteJSON(config.Logger, w, http.StatusOK, result)
}
