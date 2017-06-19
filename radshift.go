/*
A proxy for doing custom authentication in front of Redshift.
*/
package main

import (
	"github.com/uhoh-itsmaciek/femebe"
	femebebuf "github.com/uhoh-itsmaciek/femebe/buf"
	femebecore "github.com/uhoh-itsmaciek/femebe/core"
	femebeproto "github.com/uhoh-itsmaciek/femebe/proto"
	femebeutil "github.com/uhoh-itsmaciek/femebe/util"

	"gopkg.in/alecthomas/kingpin.v2"

	"database/sql"
	_ "github.com/lib/pq"

	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

// version is the current version of Radshift.
var version = "Radshift 1.0"

// tlsMinVersion is the minimum acceptable version of TLS to use (server and client)
var tlsMinVersion uint16 = tls.VersionTLS10

// backendConfig stores configuration related to the Radshift backend (Redshift).
type backendConfig struct {
	hostname          string
	port              string
	tlsCABundle       x509.CertPool
	tlsCABundlePath   string
	superuserUser     string
	superuserPassword string
}

// frontendConfig stores configuration related to the Radshift frontend (talking to clients).
type frontendConfig struct {
	listen    net.TCPAddr
	tlsConfig tls.Config
}

// authConfig stores configuration related to authenticating Radshift users.
type authConfig struct {
	linotpEndpoint url.URL
	linotpRealm    string
	linotpCABundle x509.CertPool
	users          map[string]bool
	superusers     map[string]bool
}

// Config stores the bundled configuration for Radshift as a whole.
type config struct {
	verbose  bool
	insecure bool
	frontend frontendConfig
	auth     authConfig
	backend  backendConfig
}

// logContext stores context we want to attach to session-specific log messages.
type logContext struct {
	remoteAddr net.Addr
	remoteUser string
}

// log logs a message at the given level with the current context.
func (ctx *logContext) log(level string, format string, args ...interface{}) {
	userStr := ""
	if ctx.remoteUser != "" {
		userStr = "/" + ctx.remoteUser
	}
	log.Printf(
		"%s %s%s %s",
		level,
		ctx.remoteAddr,
		userStr,
		fmt.Sprintf(format, args...))
}

// info logs a message at the INFO level with the current context.
func (ctx *logContext) info(format string, args ...interface{}) {
	ctx.log("INFO", format, args...)
}

// warn logs a message at the WARN level with the current context.
func (ctx *logContext) warn(format string, args ...interface{}) {
	ctx.log("WARN", format, args...)
}

// error logs a message at the ERROR level with the current context.
func (ctx *logContext) error(format string, args ...interface{}) {
	ctx.log("ERROR", format, args...)
}

// session stores the data needed to handle a single Radshift session.
type session struct {
	config     config
	manager    femebe.SessionManager
	clientConn net.Conn
	log        logContext
}

// main reads configuration, and accepts new sessions in a loop.
func main() {
	// http://www.retrojunkie.com/asciiart/sports/surfing.htm
	fmt.Printf("\n\n"+`
                ,@@@@@...
             ,@@@@@@@@@@@@@@..
           ,@@@@~'        `+"`"+`~@@@.
          @@@@                `+"`"+`~
         @@@@@        (_O
        @@@@@@@.       /\
        @@@@@@@@@..   |\\_,-'    %s!
        @@@@@@@@@@@@@='~
        @@@@@@@@@@@@@@@@@@@@@@@==......__
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`+"\n\n", version)
	config := getConfig()
	manager := femebe.NewSimpleSessionManager()

	// open the listening socket for frontend connections
	listen := config.frontend.listen.String()
	log.Printf("INFO - listening for postgres connections on %s...", listen)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("error listening on %s: %v", listen, err)
	}

	// accept and handle clients (each in a goroutine) forever
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("ERROR - error accepting from frontend socket: %v", err)
			continue
		}

		session := session{
			log: logContext{
				remoteAddr: clientConn.RemoteAddr(),
			},
			config:     config,
			manager:    manager,
			clientConn: clientConn,
		}

		session.log.info("accepted connection")
		go func() {
			err := session.handle()
			if err != nil {
				session.log.error(err.Error())
			}
			clientConn.Close()
		}()
	}
}

// getConfig reads configuration from the command line.
func getConfig() config {
	app := kingpin.New("radshift", "An authenticating proxy for Redshift.")
	verbose := app.Flag(
		"verbose",
		"enable verbose output.",
	).Short('v').Bool()

	insecure := app.Flag(
		"insecure",
		"Disable authentication and weaken/disable SSL (dangerous!).",
	).Bool()

	listen := app.Flag(
		"listen",
		"Interface/port on which to listen.",
	).Default("127.0.0.1:5432").TCP()

	sslCertPath := app.Flag(
		"ssl-cert",
		"Path to SSL certificate in PEM format (default: $SSL_CRT_PATH).",
	).PlaceHolder("<path/to/ssl.crt>").Required().OverrideDefaultFromEnvar("SSL_CRT_PATH").ExistingFile()

	sslKeyPath := app.Flag(
		"ssl-key",
		"Path to SSL private key in PEM format (default: $SSL_KEY_PATH).",
	).PlaceHolder("<path/to/ssl.key>").Required().OverrideDefaultFromEnvar("SSL_KEY_PATH").ExistingFile()

	redshiftLocation := app.Flag(
		"redshift",
		"Hostname/IP and port of backend Redshift cluster.",
	).PlaceHolder("<[...].redshift.amazonaws.com:5439>").Required().String()

	redshiftCABundlePath := app.Flag(
		"redshift-ca-bundle",
		"Path to Redshift Certificate Authority bundle in PEM format (see https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html).",
	).PlaceHolder("<path/to/redshift-ssl-ca-cert.pem>").Required().ExistingFile()

	redshiftUser := app.Flag(
		"redshift-user",
		"Username for the radshift superuser on the backend Redshift cluster (default $REDSHIFT_USER).",
	).Required().PlaceHolder("<user>").OverrideDefaultFromEnvar("REDSHIFT_USER").String()

	redshiftPassword := app.Flag(
		"redshift-password",
		"Password for the radshift superuser on the backend Redshift cluster (default: $REDSHIFT_PASSWORD).",
	).Required().PlaceHolder("<password>").OverrideDefaultFromEnvar("REDSHIFT_PASSWORD").String()

	users := app.Flag(
		"user",
		"Allow <username> to connect (after authenticating to LinOTP).",
	).PlaceHolder("<username>").Strings()

	superusers := app.Flag(
		"superuser",
		"Treat <username> as a superuser on the backend.",
	).PlaceHolder("<username>").Strings()

	linotpEndpoint := app.Flag(
		"linotp",
		"URL of LinOTP endpoint for verifying user OTPs",
	).PlaceHolder("<https://linotp/auth>").Required().URL()

	linotpRealm := app.Flag(
		"linotp-realm",
		"LinOTP realm for verifying user OTPs",
	).Default("radshift").String()

	linotpCABundlePath := app.Flag(
		"linotp-ca-bundle",
		"Path to CA bundle for LinOTP in PEM format (default: $SSL_CA_BUNDLE_PATH).",
	).PlaceHolder("<path/to/ca_bundle.pem>").Required().OverrideDefaultFromEnvar("SSL_CA_BUNDLE_PATH").ExistingFile()

	app.Version(version)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	// Load the TLS cert/key
	serverTLSKeyPair, err := tls.LoadX509KeyPair(*sslCertPath, *sslKeyPath)
	if err != nil {
		app.Fatalf(
			"could not read server SSL certificate/key (%q/%q): %v",
			*sslCertPath,
			*sslKeyPath,
			err)
	}
	serverTLSConfig := tls.Config{
		Certificates: []tls.Certificate{serverTLSKeyPair},
		MinVersion:   tlsMinVersion,
	}

	// load the CA certs used to verify the LinOTP conneciton
	linotpCABundlePEM, err := ioutil.ReadFile(*linotpCABundlePath)
	if err != nil {
		app.Fatalf("could not read --linotp-ca-bundle %q: %v", *linotpCABundlePath, err)
	}
	linotpCABundle := x509.NewCertPool()
	if !linotpCABundle.AppendCertsFromPEM(linotpCABundlePEM) {
		app.Fatalf("could not read --linotp-ca-bundle %q: no certs found", *linotpCABundlePath)
	}

	// load the CA certs used to verify the backend conneciton
	redshiftCABundlePEM, err := ioutil.ReadFile(*redshiftCABundlePath)
	if err != nil {
		app.Fatalf("could not read --redshift-ca-bundle %q: %v", *redshiftCABundlePath, err)
	}
	redshiftCABundle := x509.NewCertPool()
	if !redshiftCABundle.AppendCertsFromPEM(redshiftCABundlePEM) {
		app.Fatalf("could not read --redshift-ca-bundle %q: no certs found", *redshiftCABundlePath)
	}

	// make sure the --redshift parses correctly
	redshiftHostname, redshiftPort, err := net.SplitHostPort(*redshiftLocation)
	if err != nil {
		app.Fatalf("could not parse --redshift %q: %v", *redshiftLocation, err)
	}
	// make sure it resolves now too, just as a sanity check
	_, err = net.ResolveTCPAddr("tcp", *redshiftLocation)
	if err != nil {
		app.Fatalf("could not resolve --redshift %q: %v", *redshiftLocation, err)
	}

	// convert the users and superusers arrays to a map so we can search it easily
	usersMap := make(map[string]bool)
	for _, user := range *users {
		usersMap[user] = true
	}
	superusersMap := make(map[string]bool)
	for _, superuser := range *superusers {
		superusersMap[superuser] = true
		// every superuser is also a normal user
		usersMap[superuser] = true
	}

	return config{
		verbose:  *verbose,
		insecure: *insecure,
		frontend: frontendConfig{
			tlsConfig: serverTLSConfig,
			listen:    **listen,
		},
		auth: authConfig{
			linotpEndpoint: **linotpEndpoint,
			linotpRealm:    *linotpRealm,
			linotpCABundle: *linotpCABundle,
			users:          usersMap,
			superusers:     superusersMap,
		},
		backend: backendConfig{
			hostname:          redshiftHostname,
			port:              redshiftPort,
			tlsCABundle:       *redshiftCABundle,
			tlsCABundlePath:   *redshiftCABundlePath,
			superuserUser:     *redshiftUser,
			superuserPassword: *redshiftPassword,
		},
	}
}

// sendMessage sends and flushes a message on a femebe Stream.
func sendMessage(stream femebecore.Stream, msgType byte, payload []byte) (err error) {
	var msg femebecore.Message
	msg.InitFromBytes(msgType, payload)
	err = stream.Send(&msg)
	if err != nil {
		return
	}
	err = stream.Flush()
	return
}

// recvMessage receive a message from a femebe Stream and validates its type.
func recvMessage(stream femebecore.Stream, expectedMsgType byte) (*femebecore.Message, error) {
	message := new(femebecore.Message)
	err := stream.Next(message)
	if err != nil {
		return nil, err
	}
	if message.MsgType() != expectedMsgType {
		err = fmt.Errorf("expected message type %+q, got: %+q", expectedMsgType, message.MsgType())
		return nil, err
	}
	return message, nil
}

// negotiateTLS negotiates a Postgres-style TLS session with a client connection, returning the TLS-protected connection.
func (session *session) negotiateTLS() (*tls.Conn, error) {
	// wrap the connection with a buffer for easy reading/writing
	bufferedReadWrite := femebeutil.NewBufferedReadWriteCloser(session.clientConn)

	// wrap that in a femebe frontend stream so we can read the startup message
	feStream := femebecore.NewFrontendStream(bufferedReadWrite)
	var sslRequest femebecore.Message
	err := feStream.Next(&sslRequest)
	if err != nil {
		return nil, fmt.Errorf("could not read client TLS request message: %v", err)
	}

	// we only support SSL connections, so reject anything else
	if !femebeproto.IsSSLRequest(&sslRequest) {
		return nil, fmt.Errorf("only SSL connections are supported (try PGSSLMODE=verify-full)")
	}

	// flush the frontend stream before we write to the underlying connection
	err = feStream.Flush()
	if err != nil {
		return nil, fmt.Errorf("could not flush the frontend stream: %v", err)
	}

	// Send the "SSL Supported" message ('S')
	// it's not a normal "message" so we can't use the femebe helpers
	_, err = bufferedReadWrite.Write([]byte{'S'})
	if err != nil {
		return nil, fmt.Errorf("could not send 'SSL supported' message: %v", err)
	}
	err = feStream.Flush()
	if err != nil {
		return nil, fmt.Errorf("could not flush 'SSL supported' message: %v", err)
	}

	// the client should now be ready to start the TLS handshake
	tlsConn := tls.Server(session.clientConn, &session.config.frontend.tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("could not complete SSL handshake: %v\n", err)
	}

	// if Handshake() didn't fail, we've got a valid TLS session
	return tlsConn, nil
}

// getFrontendCredentials prompts the client attached to the frontend stream for a username and password.
func getFrontendCredentials(feStream *femebecore.MessageStream, startup *femebeproto.StartupMessage) (username string, password string, err error) {

	// pull out the frontend username
	username, usernameExists := startup.Params["user"]
	if (!usernameExists) || (len(username) == 0) {
		err = fmt.Errorf("could not find frontend username in startup message")
		return
	}

	// request a cleartext password from the client
	err = sendMessage(
		feStream,
		femebeproto.MsgAuthenticationCleartextPasswordR,
		[]byte{0, 0, 0, 3})
	if err != nil {
		err = fmt.Errorf("could not send frontend auth request: %v", err)
		return
	}

	// get the password response from the client
	passwordResponse, err := recvMessage(feStream, femebeproto.MsgPasswordMessageP)
	if err == io.EOF {
		return
	}
	if err != nil {
		err = fmt.Errorf("could not read frontend password: %v", err)
		return
	}

	// conver the response to a string and strip off the trailing null byte
	passwordBuf := new(bytes.Buffer)
	passwordBuf.ReadFrom(passwordResponse.Payload())
	password = passwordBuf.String()
	password = password[0 : len(password)-1]

	return
}

// checkLinOTP validates a username and OTP code against LinOTP's "/validate/check" endpoint.
func (session *session) checkLinOTP(username string, code string) (bool, error) {
	if session.config.insecure {
		session.log.warn("skipping authentication of %+q because of --insecure", username)
		return true, nil
	}

	queryParams := url.Values{}
	queryParams.Add("user", username)
	queryParams.Add("pass", code)
	queryParams.Add("realm", session.config.auth.linotpRealm)

	url := session.config.auth.linotpEndpoint
	url.RawQuery = queryParams.Encode()

	httpResponse, err := http.Get(url.String())
	if err != nil {
		return false, fmt.Errorf("error reaching LinOTP: %v", err)
	}
	defer httpResponse.Body.Close()

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return false, fmt.Errorf("error reading LinOTP response: %v", err)
	}

	type linotpResponse struct {
		Id      int
		Version string
		Jsonrpc string
		Result  struct {
			Status bool
			Value  bool
		}
	}
	var result linotpResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, fmt.Errorf("error decoding LinOTP response: %v", err)
	}

	return (result.Result.Status && result.Result.Value), nil
}

// getOrCreateBackendUser gets or creates a new "backend" user for the given frontend username, setting the backend password to a new random token valid for a short lifetime.
func (session *session) getOrCreateBackendUser(dbName string, feUsername string) (beUsername string, bePassword string, err error) {
	// do some lightweight validation on the DB name since it's user input and we're passing it to sql.Open
	matched, err := regexp.MatchString("\\A[a-zA-Z0-9_]{1,30}\\z", dbName)
	if err != nil {
		err = fmt.Errorf("could not validate database name %+q: %v", dbName, err)
		return
	}
	if !matched {
		err = fmt.Errorf("database name %+q is invalid", dbName)
		return
	}

	// validate the username against a restrictive regex as well
	matched, err = regexp.MatchString("\\A[a-zA-Z0-9_]{1,30}\\z", feUsername)
	if err != nil {
		err = fmt.Errorf("could not validate username %+q: %v", feUsername, err)
		return
	}
	if !matched {
		err = fmt.Errorf("username %+q is invalid", feUsername)
		return
	}

	// set up DB connection parameters
	params := map[string]string{
		"host":            session.config.backend.hostname,
		"port":            session.config.backend.port,
		"user":            session.config.backend.superuserUser,
		"password":        session.config.backend.superuserPassword,
		"dbname":          dbName,
		"connect_timeout": "30",
	}
	if session.config.insecure {
		session.log.warn("using weak SSL on backend connection because of --insecure")
		params["sslmode"] = "require"
	} else {
		params["sslrootcert"] = session.config.backend.tlsCABundlePath
		params["sslmode"] = "verify-full"
	}

	// format them into a string like pq wants
	paramsString := ""
	for k, v := range params {
		paramsString += fmt.Sprintf("%s=%s ", k, v)
	}

	// connect to the backend database with the parameters we chose
	db, err := sql.Open("postgres", paramsString)
	if err != nil {
		err = fmt.Errorf("error connecting to backend database: %v", err)
		return
	}

	// the backend username is the frontend one but with "_radshift" appended
	beUsername = feUsername + "_radshift"

	// generate 128 cryptographically random bits to use in the backend password
	bePasswordBytes := make([]byte, 16)
	_, err = rand.Read(bePasswordBytes)
	if err != nil {
		err = fmt.Errorf("error generating random backend password: %v", err)
		return
	}

	/*
		Redshift has some password requirements:
		 - 8 to 64 characters in length.
		 - Must contain at least one uppercase letter, one lowercase letter, and one number.
		 - Can use any printable ASCII characters (ASCII code 33 to 126) except ' (single quote), " (double quote), \, /, @, or space.

		Make sure our random password adheres to these.
	*/
	bePassword = hex.EncodeToString(bePasswordBytes) + "Aa0"

	// see if the username already exists
	userExists := false
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_user WHERE usename=$1)", beUsername).Scan(&userExists)
	if err != nil {
		err = fmt.Errorf("error checking for user in backend database: %v", err)
		return
	}

	// check if the user is one of the configured superusers and create/alter it accordingly
	var superuserClause string
	if session.config.auth.superusers[feUsername] {
		superuserClause = " CREATEUSER CREATEDB"
		session.log.info("configured as a superuser")
	} else {
		superuserClause = " NOCREATEUSER NOCREATEDB"
	}

	// create a time 30 seconds in the future for this current credential to expire
	validUntil := time.Now().UTC().Add(30 * time.Second).Format("2006-01-02 15:04:05+00")

	/*
		Construct our CREATE/ALTER USER statement manually since prepared
		statements with parameter support at the protocol level don't work
		for this case (they only work for "normal" queries, not things like
		CREATE USER or ALTER USER).

		Doing this interpolation with Sprintf is pretty dangerous but I *think*
		we're covered by the regexes we validated against above.
	*/
	if userExists {
		_, err = db.Exec(fmt.Sprintf(
			"ALTER USER %s WITH PASSWORD '%s' VALID UNTIL '%s'%s;",
			beUsername,
			bePassword,
			validUntil,
			superuserClause))
		if err != nil {
			err = fmt.Errorf("ALTER USER statement to change password failed: %v", err)
			return
		}
		session.log.info("using backend user %+q", beUsername)
	} else {
		_, err = db.Exec(fmt.Sprintf(
			"CREATE USER %s WITH PASSWORD '%s' VALID UNTIL '%s'%s;",
			beUsername,
			bePassword,
			validUntil,
			superuserClause))
		if err != nil {
			err = fmt.Errorf("CREATE USER statement failed: %v", err)
			return
		}
		session.log.info("created backend user %+q", beUsername)
	}

	return
}

// dialBackend connects to the configured backend, returning a femebe Stream.
func (session *session) dialBackend() (femebecore.Stream, error) {
	// connect to the backend
	addr := net.JoinHostPort(
		session.config.backend.hostname,
		session.config.backend.port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("could not connect to %v: %v", addr, err)
	}

	// require TLS unless the insecure flag is set
	femebeSSLConfig := femebeutil.SSLConfig{
		Config: tls.Config{
			ServerName: session.config.backend.hostname,
			RootCAs:    &session.config.backend.tlsCABundle,
			MinVersion: tlsMinVersion,
		},
		Mode: femebeutil.SSLRequire,
	}
	// in insecure mode, don't require TLS
	if session.config.insecure {
		session.log.warn("using unsafe SSL configuration for backend connection because of --insecure")
		femebeSSLConfig.Mode = femebeutil.SSLPrefer
	}

	// negotiate TLS/SSL, failing if we can't
	tlsConn, err := femebeutil.NegotiateTLS(conn, &femebeSSLConfig)
	if err != nil {
		return nil, fmt.Errorf("could not negotiate TLS with backend: %v", err)
	}

	// return a stream from the TLS-wrapped connection
	return femebecore.NewBackendStream(tlsConn), nil
}

// Cancel conects to the backend and sends a cancellation request for the given key (this method makes sure session implements the femebe Canceller interface).
func (session *session) Cancel(backendPid, secretKey uint32) error {
	beStream, err := session.dialBackend()
	defer beStream.Close()
	if err != nil {
		return err
	}
	var cancel femebecore.Message
	femebeproto.InitCancelRequest(&cancel, backendPid, secretKey)
	return beStream.Send(&cancel)
}

// authenticateToBackend authenticates to the backend (Redshift) using the given username and password.
func authenticateToBackend(beStream *femebecore.Stream, username string, password string) error {
	// receive an MD5-based authentication challenge from the server
	request, err := recvMessage(*beStream, femebeproto.MsgAuthenticationMD5PasswordR)
	if err != nil {
		return fmt.Errorf("could not read password request: %v", err)
	}

	// read the challenge type and fail if it's not MD5 like we expect
	requestType, err := femebebuf.ReadInt32(request.Payload())
	if err != nil {
		return fmt.Errorf("could not read password request type: %v", err)
	}
	if requestType != 5 {
		return fmt.Errorf("expected backend password request type 5 (MD5), got %v", requestType)
	}

	// read and return the 4 byte challenge value
	salt := make([]byte, 4)
	_, err = io.ReadFull(request.Payload(), salt)
	if err != nil {
		return fmt.Errorf("could not read password request salt: %v", err)
	}

	// compute the lowercase hex-encoded MD5 sum of a string
	md5Hex := func(x string) string {
		return fmt.Sprintf("%x", md5.Sum([]byte(x)))
	}

	// Compute an MD5 challenge response per http://www.postgresql.org/docs/9.4/static/protocol-flow.html
	// "concat('md5', md5(concat(md5(concat(password, username)), random-salt)))"
	authResponse := "md5" + md5Hex(md5Hex(password+username)+string(salt))
	authResponseBytes := append([]byte(authResponse), 0)
	err = sendMessage(*beStream, femebeproto.MsgPasswordMessageP, authResponseBytes)
	if err != nil {
		return fmt.Errorf("could not send backend auth response: %v", err)
	}

	// expect the server to tell us we authenticated successfully
	_, err = recvMessage(*beStream, femebeproto.MsgAuthenticationOkR)
	if err != nil {
		return fmt.Errorf("could not read backend auth response: %v", err)
	}

	return nil
}

// handle handles a single session from a client.
func (session *session) handle() (err error) {
	// negotiate an SSL/TLS connection to the client, getting back a wrapped connection
	tlsConn, err := session.negotiateTLS()
	if err != nil {
		return fmt.Errorf("error negotiating TLS: %v", err)
	}

	// create a frontend message stream reading from the client
	feStream := femebecore.NewFrontendStream(femebeutil.NewBufferedReadWriteCloser(tlsConn))
	var initialMessage femebecore.Message
	err = feStream.Next(&initialMessage)
	if err != nil {
		return fmt.Errorf("could not read client initial message: %v", err)
	}

	// A "cancellation request" is a special message telling us to cancel an in-progress query (Thanks TCP)
	if femebeproto.IsCancelRequest(&initialMessage) {

		// read the cancellation request
		cancelReq, err := femebeproto.ReadCancelRequest(&initialMessage)
		if err != nil {
			return fmt.Errorf("could not parse cancel message: %v", err)
		}

		// process the cancellation as requested
		err = session.manager.Cancel(cancelReq.BackendPid, cancelReq.SecretKey)
		if err != nil {
			return fmt.Errorf("could not process cancellation: %v", err)
		}

		session.log.info(
			"processed cancellation request for backend PID %d",
			cancelReq.BackendPid)
		return nil
	}

	// a "startup" message is a normal connection (client wanting to connect to make queries)
	// anything else at this point is unexpected
	if !femebeproto.IsStartupMessage(&initialMessage) {
		return fmt.Errorf("could not understand client's initial message")
	}

	// read the startup parameters, this will have the database name and username
	startup, err := femebeproto.ReadStartupMessage(&initialMessage)
	if err != nil {
		return fmt.Errorf("could not parse client startup message: %v", err)
	}

	// prompt the client for a password
	feUsername, fePassword, err := getFrontendCredentials(feStream, startup)
	if err == io.EOF {
		// this is normal behavior for a client to connect, see if it gets prompted
		// for a password, then close the connection, prompt the user for a password,
		// and retry again in a few seconds with the password in hand
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not get frontend credentials: %v", err)
	}

	// authenticate the frontend user against LinOTP
	successfullyAuthenticated, err := session.checkLinOTP(feUsername, fePassword)
	if err != nil {
		return fmt.Errorf("error checking LinOTP: %v", err)
	}
	if successfullyAuthenticated {
		session.log.remoteUser = feUsername
		session.log.info("authenticated successfully")
	} else {
		return fmt.Errorf("failed to authenticate as %+q", feUsername)
	}

	// check against our whitelist of users (TODO: convert this to use LDAP)
	if !session.config.auth.users[feUsername] {
		return fmt.Errorf("not an authorized user")
	}

	// let the client know they authenticated successfully
	err = sendMessage(feStream, femebeproto.MsgAuthenticationOkR, []byte{0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("could not send frontend auth OK response: %v", err)
	}

	dbName, dbNameExists := startup.Params["database"]
	if (!dbNameExists) || (len(dbName) == 0) {
		err = fmt.Errorf("could not find database name in startup parameters")
		return
	}

	beUsername, bePassword, err := session.getOrCreateBackendUser(dbName, feUsername)
	if err != nil {
		return fmt.Errorf("could not get/create backend user: %v", err)
	}

	// connect to the backend for the proxy connection
	beStream, err := session.dialBackend()
	if err != nil {
		return fmt.Errorf("could not connect to backend: %v", err)
	}

	// send the startup message to the backend after overwriting some bits
	startup.Params["user"] = beUsername
	delete(startup.Params, "application_name")
	var beStartup femebecore.Message
	femebeproto.InitStartupMessage(&beStartup, startup.Params)
	err = beStream.Send(&beStartup)
	if err != nil {
		return fmt.Errorf("could not send startup message to backend: %v", err)
	}

	// authenticate to the backend
	err = authenticateToBackend(&beStream, beUsername, bePassword)
	if err != nil {
		return fmt.Errorf("failed to authenticate to backend: %v", err)
	}

	// start ferrying messages back and forth between client and server
	router := femebe.NewSimpleRouter(feStream, beStream)
	err = session.manager.RunSession(
		femebe.NewSimpleSession(router, session))

	// EOF is expected, not an error in this case
	if (err != io.EOF) && (err != nil) {
		return fmt.Errorf("error proxying session: %v", err)
	}
	session.log.info("closing session")
	return nil
}
