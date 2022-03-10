package logininator

import (
	"net/http"

	"github.com/ResurgenceIT/kit/v6/identity"
	"github.com/ResurgenceIT/nerdweb/v2"
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
	Code                      string
	JWTService                identity.IJWTService
	Logger                    *logrus.Entry
	ServerPassword            string
	UserName                  string
	AdditionalData            map[string]interface{}
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
