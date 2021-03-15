package gosshgit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// Version of the gosshgit server
	Version = "0.2.0"
)

var (
	// ErrServerClosed signals the caller that the opration was requested
	// to a closed server
	ErrServerClosed = errors.New("gosshgit: server closed")

	// ErrRepositoryAlreadyExists signals the caller that given repository name is taken
	ErrRepositoryAlreadyExists = errors.New("gosshgit: repository already exists")

	errInvalidGitCommand = errors.New("gosshgit: invalid git command")
	errAccessDenied      = errors.New("gosshgit: access denied")
)

// Server accepts connections and serves git repositories to allowed clients
type Server interface {
	// Initialize creates keys and configures the server
	Initialize() error

	// Shutdown gracefully shuts down the server without interrupting
	// any active connections.
	Shutdown(ctx context.Context) error

	// Close closes all connections and shuts down the server immediately
	Close() error

	// InitBareRepo creates directory for the repository and initializes it
	InitBareRepo(name string) error
	// DeleteRepo removes the git repository with all contents
	DeleteRepo(name string) error

	// Serve starts accepting new connections and handles these
	Serve(listener net.Listener) error

	// ListenAndServe listens on TCP addres and then calls Serve
	// to handle incoming connections
	ListenAndServe(address string) error

	// Allow enables access for given public key to given repository
	Allow(publickKey string, repository string)
	// Disallow disables access for given public key
	Disallow(publickKey string, repository string)

	// PublicKey returns the ssh server public key
	PublicKey() ssh.PublicKey
}

type server struct {
	clientKeys       map[string]int
	repositoryAccess map[string]map[string]bool
	repositoryDir    string
	sshConfig        *ssh.ServerConfig
	privateKey       ed25519.PrivateKey
	publicKey        ssh.PublicKey

	listener     io.Closer
	doneChan     chan struct{}
	connections  map[io.Closer]bool
	connectionWg sync.WaitGroup
	mu           sync.Mutex
}

// New returns an server instance which will store its
// repositories to path provided
func New(repositoryPath string) Server {
	return &server{
		clientKeys:       make(map[string]int),
		repositoryAccess: make(map[string]map[string]bool),
		repositoryDir:    repositoryPath,
		sshConfig:        nil,

		doneChan:    make(chan struct{}),
		connections: make(map[io.Closer]bool),
	}
}

// Initialize generates private key for the ssh server and
// configures the server
func (srv *server) Initialize() error {
	srv.sshConfig = &ssh.ServerConfig{
		ServerVersion: fmt.Sprintf("SSH-2.0-gosshgit %s", Version),
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if !srv.keyHasAccess(keyStr) {
				return nil, errAccessDenied
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"public-key": keyStr,
				},
			}, nil
		},
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	privateSigner, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}
	srv.sshConfig.AddHostKey(privateSigner)
	srv.privateKey = privateKey
	srv.publicKey = sshPublicKey

	return nil
}
func (srv *server) Shutdown(ctx context.Context) error {
	srv.mu.Lock()
	close(srv.doneChan)
	if srv.listener != nil {
		srv.listener.Close()
	}
	srv.mu.Unlock()

	finished := make(chan struct{})
	go func() {
		srv.connectionWg.Wait()
		close(finished)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finished:
		return nil
	}
}
func (srv *server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	close(srv.doneChan)
	if srv.listener != nil {
		srv.listener.Close()
	}
	for c := range srv.connections {
		c.Close()
	}
	srv.connections = nil
	return nil
}

func (srv *server) InitBareRepo(name string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, ok := srv.repositoryAccess[name]
	if ok {
		return ErrRepositoryAlreadyExists
	}

	fullPath := filepath.Join(srv.repositoryDir, name)
	err := exec.Command("git", "init", "--bare", fullPath).Run()
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "symbolic-ref", "HEAD", "refs/heads/main")
	cmd.Dir = fullPath
	err = cmd.Run()
	if err != nil {
		return err
	}
	srv.repositoryAccess[name] = make(map[string]bool)

	return nil
}

// DeleteRepo will remove the repository permanently from the disk
func (srv *server) DeleteRepo(name string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.repositoryAccess, name)
	fullPath := filepath.Join(srv.repositoryDir, name)
	return exec.Command("rm", "-rf", fullPath).Run()
}

// Allow will grant access to all repositories for the given public key
func (srv *server) Allow(publicKey string, repository string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.clientKeys[publicKey]++
	srv.repositoryAccess[repository][publicKey] = true
}

// Disallow will remove access to all repositories from the given public key
func (srv *server) Disallow(publicKey string, repository string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.clientKeys[publicKey]--
	if srv.clientKeys[publicKey] == 0 {
		delete(srv.clientKeys, publicKey)
	}
	delete(srv.repositoryAccess[repository], publicKey)
}

// Serve accepts incoming connections on the listener
// and handles the ssh handshake before passing the connection to to goroutine
func (srv *server) Serve(listener net.Listener) error {
	defer listener.Close()
	srv.listener = listener

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			// check if server is shutting down
			select {
			case <-srv.doneChan:
				return ErrServerClosed
			default:
			}

			// is it temporary network problem
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			log.Printf("gosshgit: error accepting incoming connection: %v", err)
			return err
		}

		go srv.handleConnection(tcpConn)
	}
}
func (srv *server) ListenAndServe(address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *server) PublicKey() ssh.PublicKey {
	return srv.publicKey
}

func (srv *server) handleConnection(tcpConn net.Conn) {
	defer tcpConn.Close()
	srv.trackConnection(tcpConn, true)
	defer srv.trackConnection(tcpConn, false)

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, srv.sshConfig)
	if err != nil {
		log.Printf("gosshgit: error on handshake with '%s': %v", tcpConn.RemoteAddr(), err)
		return
	}

	log.Printf("gosshgit: new SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	defer sshConn.Close()
	srv.trackConnection(sshConn, true)
	defer srv.trackConnection(sshConn, false)

	if sshConn.User() != "git" {
		log.Printf("gosshgit: invalid user '%s'", sshConn.User())
		return
	}

	go ssh.DiscardRequests(reqs)

	clientPublicKey := sshConn.Permissions.Extensions["public-key"]

	for newChannel := range chans {
		go srv.handleChannel(newChannel, clientPublicKey)
	}
}

func (srv *server) handleChannel(channel ssh.NewChannel, clientPublicKey string) {
	if channel.ChannelType() != "session" {
		log.Printf("gosshgit: unknown channel type '%v'", channel.ChannelType())
		channel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	connection, requests, err := channel.Accept()
	if err != nil {
		log.Printf("gosshgit: channel accept failed: %v", err)
		return
	}
	defer connection.Close()

	var env []string

	for request := range requests {

		switch request.Type {
		case "env":
			var kv struct{ Key, Value string }
			err := ssh.Unmarshal(request.Payload, &kv)
			if err != nil {
				log.Printf("gosshgit: could not unmarshal env payload: %v", err)
				continue
			}
			env = append(env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))

		case "exec":
			var payload struct{ Value string }
			err := ssh.Unmarshal(request.Payload, &payload)
			if err != nil {
				log.Printf("gosshgit: could not unmarshal exec payload: %v", err)
				return
			}

			gitcmd, gitrepo, err := srv.parseCommand(payload.Value)
			if err != nil {
				log.Println("gosshgit: error parsing command:", err)
				connection.Write([]byte("Invalid command.\r\n"))
				return
			}

			if !srv.hasRepositoryAccess(clientPublicKey, gitrepo) {
				// no access
				connection.Write([]byte("Access denied.\r\n"))
				return
			}

			srv.executeCommand(connection, request, gitcmd, gitrepo, env)
			// terminate channel
			return
		default:
			// unknow request type - terminate channel
			log.Printf("gosshgit: unsupported req type: %v", request.Type)
			connection.Write([]byte("Unsupported request type.\r\n"))
			return
		}
	}
}
func (srv *server) hasRepositoryAccess(clientPublicKey string, repository string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.repositoryAccess[repository][clientPublicKey]
}

func (srv *server) trackConnection(connection io.Closer, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if add {
		srv.connections[connection] = true
		srv.connectionWg.Add(1)
	} else {
		delete(srv.connections, connection)
		srv.connectionWg.Done()
	}
}

// keyHasAccess will check if the given public key has access to the git server
func (srv *server) keyHasAccess(publicKey string) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if _, ok := srv.clientKeys[publicKey]; !ok {
		return false
	}
	return true
}

// matches (with "git " and "git-" prefixes):
// ^git upload-pack '.*'$
// ^git upload-archive '.*'$
// ^git receive-pack '.*'$
var gitCommandRegex = regexp.MustCompile(`^(git[-|\s]upload-pack|git[-|\s]upload-archive|git[-|\s]receive-pack) '(.*)'$`)

func (srv *server) parseCommand(cmd string) (string, string, error) {
	matches := gitCommandRegex.FindAllStringSubmatch(cmd, 1)
	if len(matches) == 0 {
		return "", "", errInvalidGitCommand
	}
	command := matches[0][1]
	repo := strings.Replace(matches[0][2], "/", "", 1)

	return command, repo, nil
}

func (srv *server) executeCommand(channel ssh.Channel, request *ssh.Request, command string, repo string, env []string) {
	cmd := exec.Command(command, repo)
	cmd.Dir = srv.repositoryDir
	cmd.Env = env

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	input, _ := cmd.StdinPipe()

	err := cmd.Start()
	if err != nil {
		log.Printf("gosshgit: command start error: %v", err)
		return
	}

	request.Reply(true, nil)
	go io.Copy(input, channel)
	io.Copy(channel, stdout)
	io.Copy(channel.Stderr(), stderr)

	err = cmd.Wait()
	if err != nil {
		log.Printf("gosshgit: command failed: %v", err)
		return
	}

	channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}
