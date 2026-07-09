package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const version = "0.1.0"

type Server struct {
	mu        sync.Mutex
	dataDir   string
	state     State
	stateFile string
}

type State struct {
	Targets       []Target     `json:"targets"`
	APIKeys       []APIKey     `json:"apiKeys"`
	APIKeyHistory []APIKey     `json:"apiKeyHistory,omitempty"`
	Leases        []Lease      `json:"leases"`
	LeaseHistory  []Lease      `json:"leaseHistory,omitempty"`
	OpsLinks      []OpsLink    `json:"opsLinks"`
	OpsSessions   []OpsSession `json:"opsSessions"`
	Events        []AuditEvent `json:"events"`
}

type Target struct {
	ID                string     `json:"target"`
	DisplayName       string     `json:"displayName"`
	Host              string     `json:"host"`
	SSHPort           int        `json:"sshPort"`
	AgentSecret       string     `json:"agentSecret,omitempty"`
	State             string     `json:"state"`
	AgentStatus       string     `json:"agentStatus"`
	BootstrapStatus   string     `json:"bootstrapStatus"`
	BootstrapMessage  string     `json:"bootstrapMessage,omitempty"`
	RemovalMode       string     `json:"removalMode,omitempty"`
	RemovalCommandID  string     `json:"removalCommandId,omitempty"`
	RemovalReason     string     `json:"removalReason,omitempty"`
	RemovalRequested  *time.Time `json:"removalRequestedAt,omitempty"`
	RemovalDeadline   *time.Time `json:"removalDeadline,omitempty"`
	AllowedRoles      []string   `json:"allowedRoles"`
	AllowedProfiles   []string   `json:"allowedAccessProfiles"`
	AllowedLinuxUsers []string   `json:"allowedLinuxUsers,omitempty"`
	MaxTTLSeconds     int        `json:"maxTtlSeconds"`
}

type APIKey struct {
	ID            string     `json:"id"`
	RequesterID   string     `json:"requesterId"`
	DisplayName   string     `json:"displayName"`
	RequesterType string     `json:"requesterType"`
	Hash          string     `json:"hash"`
	PolicyGroups  []string   `json:"policyGroups"`
	CreatedAt     time.Time  `json:"createdAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
}

type Lease struct {
	ID             string       `json:"leaseId"`
	Version        int          `json:"version"`
	Generation     int          `json:"generation"`
	CaseID         string       `json:"caseId,omitempty"`
	State          string       `json:"state"`
	RequesterID    string       `json:"requesterId"`
	Target         string       `json:"target"`
	Host           string       `json:"host"`
	Role           string       `json:"role"`
	AccessProfile  string       `json:"accessProfile"`
	LinuxUser      string       `json:"linuxUser"`
	PublicKey      string       `json:"publicKey,omitempty"`
	KeyFingerprint string       `json:"keyFingerprint,omitempty"`
	KeyDelivery    string       `json:"keyDelivery"`
	Reason         string       `json:"reason"`
	Timeframe      Timeframe    `json:"timeframe"`
	Restrictions   Restrictions `json:"restrictions"`
	CreatedAt      time.Time    `json:"createdAt"`
	ApprovedAt     *time.Time   `json:"approvedAt,omitempty"`
	ApprovedBy     string       `json:"approvedBy,omitempty"`
	ExpiresAt      *time.Time   `json:"expiresAt,omitempty"`
}

type Timeframe struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds,omitempty"`
}

type Restrictions struct {
	PTY             bool `json:"pty"`
	AgentForwarding bool `json:"agentForwarding"`
	X11Forwarding   bool `json:"x11Forwarding"`
	PortForwarding  bool `json:"portForwarding"`
}

const (
	accessProfileNormal   = "normal"
	accessProfileElevated = "elevated"
)

var accessProfileLinuxUsers = map[string]string{
	accessProfileNormal:   "accessgate-normal",
	accessProfileElevated: "accessgate-elevated",
}

var accessProfileGroups = map[string]string{
	accessProfileNormal:   "accessgate-normal",
	accessProfileElevated: "accessgate-elevated",
}

type OpsLink struct {
	TokenHash  string     `json:"tokenHash"`
	Operator   string     `json:"operator"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	ConsumedAt *time.Time `json:"consumedAt,omitempty"`
	SessionID  string     `json:"sessionId,omitempty"`
}

type OpsSession struct {
	ID        string    `json:"id"`
	Operator  string    `json:"operator"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type AuditEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Actor     string    `json:"actor"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type createLeaseRequest struct {
	Target        string       `json:"target"`
	Role          string       `json:"role"`
	AccessProfile string       `json:"accessProfile"`
	LinuxUser     string       `json:"linuxUser"`
	TTLSeconds    int          `json:"ttlSeconds"`
	Timeframe     Timeframe    `json:"timeframe"`
	Restrictions  Restrictions `json:"restrictions"`
	Reason        string       `json:"reason"`
}

type BootstrapCredentials struct {
	User                 string
	AuthMethod           string
	Password             string
	PrivateKey           string
	PrivateKeyPassphrase string
}

func main() {
	agentMode := flag.Bool("agent", false, "run AccessGate agent")
	agentAddr := flag.String("agent-addr", "127.0.0.1:9187", "agent listen address")
	agentID := flag.String("agent-id", "", "agent target id")
	agentServerURL := flag.String("server-url", "", "AG-Server URL for desired-state polling")
	agentSecret := flag.String("agent-secret", "", "AG-Agent shared secret")
	agentSecretFile := flag.String("agent-secret-file", "", "AG-Agent shared secret file")
	agentAutoUpdate := flag.Bool("agent-auto-update", true, "enable AG-Agent self update")
	opsKey := flag.Bool("opskey", false, "create one-time operator login link")
	opsClear := flag.Bool("ops-clear", false, "expire all active operator login links and sessions")
	operator := flag.String("operator", "operator", "operator label")
	ttl := flag.Duration("ttl", time.Hour, "ops link ttl")
	baseURL := flag.String("base-url", "", "public base URL override")
	flag.Parse()

	if *agentMode {
		runAgent(*agentAddr, *agentID, *agentServerURL, loadAgentSecret(*agentSecret, *agentSecretFile), *agentAutoUpdate)
		return
	}

	dataDir := env("ACCESSGATE_DATA_DIR", "./data")
	srv, err := NewServer(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.loadOrInit(); err != nil {
		log.Fatal(err)
	}

	if *opsKey {
		if link, handled, err := createOpsLinkViaRunningServer(*operator, *ttl, *baseURL); handled {
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(link)
			return
		}
		link, err := srv.createOpsLink(*operator, *ttl, *baseURL)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(link)
		return
	}
	if *opsClear {
		count, err := srv.clearOpsAccess(*operator)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("expired %d ops links/sessions\n", count)
		return
	}

	addr := env("ACCESSGATE_ADDR", ":8080")
	mux := http.NewServeMux()
	srv.routes(mux)
	log.Printf("AccessGate %s listening on %s", version, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func NewServer(dataDir string) (*Server, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return &Server{dataDir: dataDir, stateFile: filepath.Join(dataDir, "state.json")}, nil
}

func loadAgentSecret(secret, secretFile string) string {
	if secret != "" {
		return strings.TrimSpace(secret)
	}
	if secretFile == "" {
		return ""
	}
	b, err := os.ReadFile(secretFile)
	if err != nil {
		log.Printf("agent secret file read failed: %v", err)
		return ""
	}
	return strings.TrimSpace(string(b))
}

func runAgent(addr, agentID, serverURL, agentSecret string, autoUpdate bool) {
	ensureAgentRuntimeDirs()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "AccessGate AG-Agent", "version": version, "state": "ok"})
	})
	if agentID != "" && agentSecret != "" {
		mux.HandleFunc("/v1/agent/leases/", func(w http.ResponseWriter, r *http.Request) {
			agentLeaseNotify(w, r, agentID, agentSecret, serverURL)
		})
	}
	if agentID != "" && serverURL != "" {
		if agentSecret == "" {
			log.Printf("agent secret missing; AG-Server communication is disabled")
		} else {
			go pollDesiredState(agentID, serverURL, agentSecret)
		}
		if autoUpdate {
			if agentSecret == "" {
				log.Printf("agent secret missing; auto update is disabled")
			} else {
				go pollAgentUpdate(agentID, serverURL, agentSecret)
			}
		}
	}
	log.Printf("AccessGate AG-Agent %s listening on %s", version, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func ensureAgentRuntimeDirs() {
	for _, dir := range []string{"/var/lib/accessgate-agent", "/var/log/accessgate-agent"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("agent runtime dir %s create failed: %v", dir, err)
		}
	}
}

func agentLeaseNotify(w http.ResponseWriter, r *http.Request, agentID, agentSecret, serverURL string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if !verifySignedRequest(w, r, agentID, agentSecret) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/agent/leases/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "revoke-notify" {
		writeError(w, http.StatusNotFound, "not_found", "lease notify endpoint not found")
		return
	}
	var req struct {
		LeaseID    string `json:"leaseId"`
		LinuxUser  string `json:"linuxUser"`
		Version    int    `json:"version"`
		Generation int    `json:"generation"`
		Mode       string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.LeaseID == "" {
		req.LeaseID = parts[0]
	}
	if req.LeaseID != parts[0] || req.LinuxUser == "" {
		writeError(w, http.StatusBadRequest, "invalid_revoke", "leaseId and linuxUser are required")
		return
	}
	if err := removeManagedLeaseKey(req.LinuxUser, req.LeaseID); err != nil {
		writeError(w, http.StatusInternalServerError, "key_remove_failed", err.Error())
		return
	}
	killLinuxUserSessions(req.LinuxUser)
	if serverURL != "" {
		go func() {
			_ = fetchAndApplyDesiredState(agentID, strings.TrimRight(serverURL, "/"), agentSecret)
		}()
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "revoked", "leaseId": req.LeaseID})
}

func pollAgentUpdate(agentID, serverURL, agentSecret string) {
	serverURL = strings.TrimRight(serverURL, "/")
	time.Sleep(10 * time.Second)
	for {
		if err := checkAndApplyAgentUpdate(agentID, serverURL, agentSecret); err != nil {
			log.Printf("agent update check failed: %v", err)
		}
		time.Sleep(60 * time.Second)
	}
}

type agentUpdateMeta struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	URL     string `json:"url"`
}

func checkAndApplyAgentUpdate(agentID, serverURL, agentSecret string) error {
	goarch := runtime.GOARCH
	var meta agentUpdateMeta
	if err := agentGetJSON(agentID, agentSecret, serverURL+"/v1/agent-binaries/"+goarch+"/meta", &meta); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	localSHA, _, err := fileSHA256(exe)
	if err != nil {
		return err
	}
	if strings.EqualFold(localSHA, meta.SHA256) {
		return nil
	}
	downloadURL := meta.URL
	if strings.HasPrefix(downloadURL, "/") {
		downloadURL = serverURL + downloadURL
	}
	if err := downloadAndInstallAgent(agentID, agentSecret, downloadURL, meta.SHA256, exe); err != nil {
		return err
	}
	log.Printf("agent updated to %s sha256=%s; restarting service", meta.Version, meta.SHA256)
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "accessgate-agent").Run()
	}()
	return nil
}

func downloadAndInstallAgent(agentID, agentSecret, url, expectedSHA, dest string) error {
	req, err := newAgentRequest(http.MethodGet, url, nil, agentID, agentSecret)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	var source io.Reader = resp.Body
	if resp.Header.Get("X-AccessGate-Encrypted") == "aesgcm-v1" {
		var env encryptedEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			return err
		}
		plain, err := decryptAgentEnvelope(agentSecret, env)
		if err != nil {
			return err
		}
		source = bytes.NewReader(plain)
	}
	tmp := dest + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), source)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedSHA) {
		_ = os.Remove(tmp)
		return fmt.Errorf("download hash mismatch: got %s expected %s", actual, expectedSHA)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func pollDesiredState(agentID, serverURL, agentSecret string) {
	serverURL = strings.TrimRight(serverURL, "/")
	for {
		if err := fetchAndApplyDesiredState(agentID, serverURL, agentSecret); err != nil {
			log.Printf("desired-state apply failed: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
}

type desiredStateResponse struct {
	AgentID             string         `json:"agentId"`
	DesiredStateVersion int            `json:"desiredStateVersion"`
	Leases              []AgentLease   `json:"leases"`
	Commands            []AgentCommand `json:"commands,omitempty"`
}

type AgentCommand struct {
	CommandID  string    `json:"commandId"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	AgentID    string    `json:"agentId"`
	Generation int       `json:"generation"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type AgentLease struct {
	LeaseID       string       `json:"leaseId"`
	Version       int          `json:"version"`
	Generation    int          `json:"generation"`
	State         string       `json:"state"`
	AccessProfile string       `json:"accessProfile"`
	LinuxUser     string       `json:"linuxUser"`
	PublicKey     string       `json:"publicKey"`
	ExpiresAt     *time.Time   `json:"expiresAt,omitempty"`
	Restrictions  Restrictions `json:"restrictions"`
}

func fetchAndApplyDesiredState(agentID, serverURL, agentSecret string) error {
	var desired desiredStateResponse
	if err := agentGetJSON(agentID, agentSecret, serverURL+"/v1/agents/"+agentID+"/desired-state", &desired); err != nil {
		return err
	}
	if err := applyDesiredState(desired.Leases); err != nil {
		return err
	}
	return applyAgentCommands(agentID, serverURL, agentSecret, desired.Commands)
}

func applyAgentCommands(agentID, serverURL, agentSecret string, commands []AgentCommand) error {
	now := time.Now().UTC()
	for _, cmd := range commands {
		if cmd.AgentID != agentID || now.After(cmd.ExpiresAt) {
			continue
		}
		switch cmd.Action {
		case "retire", "tombstone":
			_ = reportAgentEvent(agentID, serverURL, agentSecret, cmd.CommandID, cmd.Action+".accepted", "")
			if err := destroyAccessGateAgent(cmd.Action); err != nil {
				_ = reportAgentEvent(agentID, serverURL, agentSecret, cmd.CommandID, cmd.Action+".failed", err.Error())
				return err
			}
			_ = reportAgentEvent(agentID, serverURL, agentSecret, cmd.CommandID, cmd.Action+".completed", "")
			return nil
		}
	}
	return nil
}

func reportAgentEvent(agentID, serverURL, agentSecret, commandID, eventType, message string) error {
	body, err := json.Marshal(map[string]string{"commandId": commandID, "type": eventType, "message": message})
	if err != nil {
		return err
	}
	req, err := newAgentRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/agents/"+agentID+"/events", body, agentID, agentSecret)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agent event status %d", resp.StatusCode)
	}
	return nil
}

type encryptedEnvelope struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
}

func agentGetJSON(agentID, agentSecret, url string, out any) error {
	req, err := newAgentRequest(http.MethodGet, url, nil, agentID, agentSecret)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent request status %d", resp.StatusCode)
	}
	if resp.Header.Get("X-AccessGate-Encrypted") == "aesgcm-v1" {
		var env encryptedEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			return err
		}
		plain, err := decryptAgentEnvelope(agentSecret, env)
		if err != nil {
			return err
		}
		return json.Unmarshal(plain, out)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func newAgentRequest(method, url string, body []byte, agentID, agentSecret string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	signAgentRequest(req, body, agentID, agentSecret)
	return req, nil
}

func signAgentRequest(req *http.Request, body []byte, agentID, agentSecret string) {
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce := token(18)
	bodyHash := sha256.Sum256(body)
	req.Header.Set("X-AccessGate-Agent-ID", agentID)
	req.Header.Set("X-AccessGate-Agent-Timestamp", ts)
	req.Header.Set("X-AccessGate-Agent-Nonce", nonce)
	req.Header.Set("X-AccessGate-Agent-Encrypted", "aesgcm-v1")
	req.Header.Set("X-AccessGate-Agent-Signature", agentSignature(agentSecret, req.Method, req.URL.EscapedPath(), ts, nonce, hex.EncodeToString(bodyHash[:])))
}

func verifySignedRequest(w http.ResponseWriter, r *http.Request, expectedAgentID, secret string) bool {
	agentID := r.Header.Get("X-AccessGate-Agent-ID")
	ts := r.Header.Get("X-AccessGate-Agent-Timestamp")
	nonce := r.Header.Get("X-AccessGate-Agent-Nonce")
	sig := r.Header.Get("X-AccessGate-Agent-Signature")
	if agentID == "" || ts == "" || nonce == "" || sig == "" {
		writeError(w, http.StatusUnauthorized, "agent_auth_required", "missing agent authentication headers")
		return false
	}
	if expectedAgentID != "" && agentID != expectedAgentID {
		writeError(w, http.StatusForbidden, "agent_id_mismatch", "agent identity does not match endpoint")
		return false
	}
	when, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "agent_auth_invalid", "invalid agent timestamp")
		return false
	}
	if d := time.Since(time.Unix(when, 0).UTC()); d > 2*time.Minute || d < -2*time.Minute {
		writeError(w, http.StatusUnauthorized, "agent_auth_stale", "agent timestamp outside allowed window")
		return false
	}
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "agent_body_read_failed", err.Error())
			return false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	bodySHA := sha256.Sum256(body)
	expected := agentSignature(secret, r.Method, r.URL.EscapedPath(), ts, nonce, hex.EncodeToString(bodySHA[:]))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		writeError(w, http.StatusUnauthorized, "agent_auth_invalid", "invalid agent signature")
		return false
	}
	return true
}

func agentSignature(secret, method, path, ts, nonce, bodySHA string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + bodySHA))
	return hex.EncodeToString(mac.Sum(nil))
}

func decryptAgentEnvelope(secret string, env encryptedEnvelope) ([]byte, error) {
	if env.Alg != "aesgcm-v1" {
		return nil, fmt.Errorf("unsupported envelope alg %q", env.Alg)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	data, err := base64.RawURLEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, err
	}
	aead, err := agentAEAD(secret)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, data, nil)
}

func encryptAgentEnvelope(secret string, plain []byte) (encryptedEnvelope, error) {
	aead, err := agentAEAD(secret)
	if err != nil {
		return encryptedEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedEnvelope{}, err
	}
	data := aead.Seal(nil, nonce, plain, nil)
	return encryptedEnvelope{
		Alg:   "aesgcm-v1",
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Data:  base64.RawURLEncoding.EncodeToString(data),
	}, nil
}

func agentAEAD(secret string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("accessgate-agent-channel-v1:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func applyDesiredState(leases []AgentLease) error {
	byUser := map[string][]AgentLease{}
	now := time.Now().UTC()
	for _, lease := range leases {
		if lease.State != "active" || lease.PublicKey == "" || lease.LinuxUser == "" {
			continue
		}
		if lease.AccessProfile == "" {
			lease.AccessProfile = accessProfileForLinuxUser(lease.LinuxUser)
		}
		if _, ok := accessProfileLinuxUsers[lease.AccessProfile]; !ok {
			continue
		}
		if lease.ExpiresAt != nil && !now.Before(*lease.ExpiresAt) {
			continue
		}
		byUser[lease.LinuxUser] = append(byUser[lease.LinuxUser], lease)
	}
	for user, userLeases := range byUser {
		if err := ensureManagedAccessUser(user, userLeases[0].AccessProfile); err != nil {
			return err
		}
		if err := writeAuthorizedKeys(user, userLeases); err != nil {
			return err
		}
	}
	for _, user := range knownAccessGateUsers() {
		if _, ok := byUser[user]; !ok {
			if err := writeAuthorizedKeys(user, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func destroyAccessGateAgent(action string) error {
	for _, user := range knownAccessGateUsers() {
		home, err := userHome(user)
		if err != nil {
			continue
		}
		_ = os.Remove(filepath.Join(home, ".ssh", "authorized_keys_accessgate"))
	}
	script := `#!/bin/sh
set -eu
sleep 2
systemctl disable accessgate-agent >/dev/null 2>&1 || true
rm -f /home/accessgate-normal/.ssh/authorized_keys_accessgate
rm -f /home/accessgate-elevated/.ssh/authorized_keys_accessgate
rm -f /usr/local/bin/accessgate-agent
rm -f /etc/systemd/system/accessgate-agent.service
rm -rf /etc/accessgate-agent
rm -rf /var/lib/accessgate-agent
rm -rf /var/log/accessgate-agent
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl stop accessgate-agent >/dev/null 2>&1 || true
systemctl reset-failed accessgate-agent >/dev/null 2>&1 || true
rm -f "$0"
`
	path := filepath.Join(os.TempDir(), "accessgate-"+action+"-"+token(8)+".sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return err
	}
	unit := "accessgate-agent-uninstall-" + action + "-" + token(8)
	cmd := "systemd-run --unit=" + shellQuote(unit) + " --collect --property=Type=oneshot /bin/sh " + shellQuote(path) + " >/dev/null 2>&1 || nohup /bin/sh " + shellQuote(path) + " >/dev/null 2>&1 &"
	if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
		return err
	}
	return nil
}

func knownAccessGateUsers() []string {
	users := []string{}
	for _, linuxUser := range accessProfileLinuxUsers {
		if err := exec.Command("id", "-u", linuxUser).Run(); err == nil {
			users = append(users, linuxUser)
		}
	}
	return uniqueStrings(users)
}

func ensureManagedAccessUser(linuxUser, profile string) error {
	expectedUser, ok := accessProfileLinuxUsers[profile]
	if !ok {
		return fmt.Errorf("unsupported access profile %q", profile)
	}
	if linuxUser != expectedUser {
		return fmt.Errorf("access profile %q must use managed user %q", profile, expectedUser)
	}
	group := accessProfileGroups[profile]
	if group == "" || !strings.HasPrefix(group, "accessgate-") {
		return fmt.Errorf("unsafe access group %q", group)
	}
	if err := exec.Command("getent", "group", group).Run(); err != nil {
		if err := exec.Command("groupadd", "--system", group).Run(); err != nil {
			return fmt.Errorf("create group %s: %w", group, err)
		}
	}
	if err := exec.Command("id", "-u", linuxUser).Run(); err != nil {
		if err := exec.Command("useradd", "--system", "--create-home", "--home-dir", filepath.Join("/home", linuxUser), "--shell", "/bin/bash", "--gid", group, linuxUser).Run(); err != nil {
			return fmt.Errorf("create user %s: %w", linuxUser, err)
		}
	}
	if err := exec.Command("usermod", "-a", "-G", group, linuxUser).Run(); err != nil {
		return fmt.Errorf("add user %s to group %s: %w", linuxUser, group, err)
	}
	if profile == accessProfileElevated {
		if err := ensureElevatedSudoers(group); err != nil {
			return err
		}
	}
	return nil
}

func ensureElevatedSudoers(group string) error {
	if group != accessProfileGroups[accessProfileElevated] {
		return fmt.Errorf("refusing sudoers rule for unmanaged group %q", group)
	}
	if err := os.MkdirAll("/etc/sudoers.d", 0o755); err != nil {
		return err
	}
	path := "/etc/sudoers.d/accessgate-elevated"
	content := "%" + group + " ALL=(ALL) NOPASSWD:ALL\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return err
	}
	if err := exec.Command("visudo", "-cf", tmp).Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("validate sudoers: %w", err)
	}
	return os.Rename(tmp, path)
}

func writeAuthorizedKeys(linuxUser string, leases []AgentLease) error {
	home, err := userHome(linuxUser)
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	lines := []string{}
	for _, lease := range leases {
		lines = append(lines, renderAuthorizedKeyLine(lease))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	path := filepath.Join(sshDir, "authorized_keys_accessgate")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	_ = exec.Command("chown", linuxUser+":"+linuxUser, sshDir).Run()
	_ = exec.Command("chown", linuxUser+":"+linuxUser, tmp).Run()
	return os.Rename(tmp, path)
}

func removeManagedLeaseKey(linuxUser, leaseID string) error {
	home, err := userHome(linuxUser)
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".ssh", "authorized_keys_accessgate")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	kept := make([]string, 0, len(lines))
	marker := "accessgate:lease=" + leaseID
	for _, line := range lines {
		if strings.Contains(line, marker) {
			continue
		}
		if strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	return writeAuthorizedKeyLines(linuxUser, kept)
}

func writeAuthorizedKeyLines(linuxUser string, lines []string) error {
	home, err := userHome(linuxUser)
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(sshDir, "authorized_keys_accessgate")
	tmp := path + ".tmp"
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	_ = exec.Command("chown", linuxUser+":"+linuxUser, sshDir).Run()
	_ = exec.Command("chown", linuxUser+":"+linuxUser, tmp).Run()
	return os.Rename(tmp, path)
}

func killLinuxUserSessions(linuxUser string) {
	if linuxUser == "" {
		return
	}
	out, err := exec.Command("ps", "-eo", "pid=,comm=,args=").Output()
	if err != nil {
		return
	}
	pids := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid := fields[0]
		comm := fields[1]
		args := strings.Join(fields[2:], " ")
		if !strings.Contains(comm, "sshd") || !strings.Contains(args, "sshd:") {
			continue
		}
		if strings.Contains(args, "sshd: "+linuxUser+"@") || strings.Contains(args, "sshd: "+linuxUser+" ") {
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 {
		return
	}
	_ = exec.Command("kill", append([]string{"-TERM"}, pids...)...).Run()
	time.Sleep(500 * time.Millisecond)
	_ = exec.Command("kill", append([]string{"-KILL"}, pids...)...).Run()
}

func renderAuthorizedKeyLine(lease AgentLease) string {
	options := []string{"no-agent-forwarding", "no-X11-forwarding", "no-port-forwarding"}
	if !lease.Restrictions.PTY {
		options = append(options, "no-pty")
	}
	return strings.Join(options, ",") + " " + strings.TrimSpace(lease.PublicKey) + " accessgate:lease=" + lease.LeaseID
}

func userHome(linuxUser string) (string, error) {
	if linuxUser == "root" {
		return "/root", nil
	}
	out, err := exec.Command("getent", "passwd", linuxUser).Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(out)), ":")
		if len(parts) >= 6 && parts[5] != "" {
			return parts[5], nil
		}
	}
	return filepath.Join("/home", linuxUser), nil
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/v1/informer/agent-contract", s.informerAgentContract)
	mux.HandleFunc("/v1/informer", s.informer)
	mux.HandleFunc("/v1/informer/process", s.informerProcess)
	mux.HandleFunc("/v1/informer/schema", s.informerSchema)
	mux.HandleFunc("/v1/informer/errors", s.informerErrors)
	mux.HandleFunc("/v1/internal/ops-link", s.internalOpsLink)
	mux.HandleFunc("/v1/agent-binaries/", s.agentBinary)
	mux.HandleFunc("/v1/targets", s.targets)
	mux.HandleFunc("/v1/leases", s.leases)
	mux.HandleFunc("/v1/leases/", s.leaseAction)
	mux.HandleFunc("/v1/access-cases/", s.claimCase)
	mux.HandleFunc("/v1/agents/", s.agentDesiredState)
	mux.HandleFunc("/v1/admin/api-keys", s.adminAPIKeys)
	mux.HandleFunc("/v1/admin/api-keys/", s.adminAPIKeyAction)
	mux.HandleFunc("/v1/admin/targets", s.adminTargets)
	mux.HandleFunc("/v1/admin/targets/", s.adminTargetAction)
	mux.HandleFunc("/ops/", s.consumeOpsLink)
	mux.HandleFunc("/ops/status", s.opsStatus)
	mux.HandleFunc("/ops", s.opsPanel)
}

func (s *Server) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, err := os.ReadFile(s.stateFile); err == nil {
		if len(strings.TrimSpace(string(b))) > 0 {
			if err := json.Unmarshal(b, &s.state); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(s.state.Targets) == 0 {
		s.state.Targets = defaultTargets()
	}
	for i := range s.state.Targets {
		if s.state.Targets[i].State == "" {
			s.state.Targets[i].State = "active"
		}
		if s.state.Targets[i].AgentStatus == "" {
			s.state.Targets[i].AgentStatus = "verified"
		}
		if s.state.Targets[i].BootstrapStatus == "" {
			s.state.Targets[i].BootstrapStatus = "complete"
		}
		if s.state.Targets[i].SSHPort == 0 {
			s.state.Targets[i].SSHPort = 22
		}
		if len(s.state.Targets[i].AllowedProfiles) == 0 {
			s.state.Targets[i].AllowedProfiles = defaultAccessProfiles()
		}
		s.state.Targets[i].AllowedLinuxUsers = nil
	}
	for i := range s.state.Leases {
		if s.state.Leases[i].AccessProfile == "" {
			s.state.Leases[i].AccessProfile = accessProfileForLinuxUser(s.state.Leases[i].LinuxUser)
		}
		if user, ok := accessProfileLinuxUsers[s.state.Leases[i].AccessProfile]; ok {
			s.state.Leases[i].LinuxUser = user
		}
	}
	s.migrateHistoryLocked()
	s.expireLeasesLocked(time.Now().UTC())
	if key := os.Getenv("ACCESSGATE_BOOTSTRAP_API_KEY"); key != "" && !s.hasAPIKeyHash(hashSecret(key)) {
		s.state.APIKeys = append(s.state.APIKeys, APIKey{
			ID: "agkey_bootstrap", RequesterID: "req_bootstrap", DisplayName: "bootstrap",
			RequesterType: "service", Hash: hashSecret(key), PolicyGroups: []string{"bootstrap"},
			CreatedAt: time.Now().UTC(),
		})
	}
	return s.saveLocked()
}

func (s *Server) migrateHistoryLocked() {
	activeLeases := s.state.Leases[:0]
	for _, lease := range s.state.Leases {
		switch lease.State {
		case "expired", "revoked":
			s.archiveLeaseLocked(lease)
		default:
			activeLeases = append(activeLeases, lease)
		}
	}
	s.state.Leases = activeLeases

	activeKeys := s.state.APIKeys[:0]
	for _, key := range s.state.APIKeys {
		if key.RevokedAt != nil {
			s.archiveAPIKeyLocked(key)
			continue
		}
		activeKeys = append(activeKeys, key)
	}
	s.state.APIKeys = activeKeys
}

func (s *Server) reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.stateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.state)
}

func (s *Server) saveLocked() error {
	tmp := s.stateFile + ".tmp"
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.stateFile)
}

func defaultTargets() []Target {
	return []Target{
		{ID: "server-a", DisplayName: "server-a", Host: "10.0.0.11", SSHPort: 22, State: "active", AgentStatus: "verified", BootstrapStatus: "complete", AllowedRoles: []string{"normal", "serviceuser"}, AllowedProfiles: []string{"normal", "elevated"}, MaxTTLSeconds: 3600},
		{ID: "server-b", DisplayName: "server-b", Host: "10.0.0.12", SSHPort: 22, State: "active", AgentStatus: "verified", BootstrapStatus: "complete", AllowedRoles: []string{"normal", "serviceuser"}, AllowedProfiles: []string{"normal", "elevated"}, MaxTTLSeconds: 3600},
		{ID: "server-c", DisplayName: "server-c", Host: "10.0.0.13", SSHPort: 22, State: "active", AgentStatus: "verified", BootstrapStatus: "complete", AllowedRoles: []string{"normal", "serviceuser"}, AllowedProfiles: []string{"normal", "elevated"}, MaxTTLSeconds: 3600},
		{ID: "server-d", DisplayName: "server-d", Host: "10.0.0.14", SSHPort: 22, State: "active", AgentStatus: "verified", BootstrapStatus: "complete", AllowedRoles: []string{"normal", "serviceuser"}, AllowedProfiles: []string{"normal", "elevated"}, MaxTTLSeconds: 3600},
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"service": "AccessGate", "version": version, "state": "ok"})
}

func (s *Server) informer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "AccessGate", "apiVersion": "v1", "purpose": "Request and manage time-limited SSH access leases.",
		"authRequiredForAccessRequests": true,
		"publicEndpoints":               []string{"GET /v1/informer", "GET /v1/informer/agent-contract", "GET /v1/informer/process", "GET /v1/informer/schema", "GET /v1/informer/errors"},
		"authenticatedEndpoints":        []string{"GET /v1/targets", "POST /v1/leases", "POST /v1/access-cases/{caseId}/claim", "GET /v1/leases/{leaseId}", "POST /v1/leases/{leaseId}/revoke"},
		"accessProfiles":                []string{"normal", "elevated"},
		"agentContract":                 "GET /v1/informer/agent-contract",
		"recommendedFlow":               "Call POST /v1/leases with target, role, accessProfile, timeframe, and reason. AccessGate maps the profile to an AccessGate-owned local user, generates a unique lease key pair, and returns private key material exactly once.",
	})
}

func (s *Server) informerProcess(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"normalProfile":              []string{"Submit accessProfile=normal for a managed AccessGate user without sudo.", "The AG-Agent maps this profile to accessgate-normal and the accessgate-normal group."},
		"elevatedProfile":            []string{"Submit accessProfile=elevated for a managed AccessGate user with passwordless sudo.", "The AG-Agent maps this profile to accessgate-elevated and the accessgate-elevated group."},
		"normalAccess":               []string{"Submit role=normal and timeframe.type=duration.", "Keep timeframe.seconds at or below 3600.", "Receive generated private key exactly once when state=active.", "Temporarily store the private key with restrictive permissions and connect with ssh -i <key> <linuxUser>@<host>.", "Stop using the lease before expiresAt.", "Always call POST /v1/leases/{leaseId}/revoke in cleanup/finally."},
		"unlimitedServiceuserAccess": []string{"Submit role=serviceuser and timeframe.type=unlimited.", "Store caseId when state=pending_approval.", "Wait for human approval in the Web UI.", "Call POST /v1/access-cases/{caseId}/claim.", "Receive generated private key material exactly once after claim succeeds."},
		"sshPropagation":             map[string]any{"expectedSeconds": 5, "clientBehavior": "Retry SSH for a short window after active lease creation because the AG-Agent applies desired state asynchronously."},
		"requiredFields":             []string{"target", "role", "accessProfile", "timeframe", "reason"},
	})
}

func (s *Server) informerSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, agentContractSchemas())
}

func (s *Server) informerErrors(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"errors": agentContractErrors()})
}

func (s *Server) informerAgentContract(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":         "AccessGate",
		"apiVersion":      "v1",
		"contractVersion": "2026-07-09.agent-contract.v1",
		"purpose":         "Machine-readable contract for AI agents requesting temporary SSH access leases.",
		"authentication": map[string]any{
			"scheme":      "Bearer client API key",
			"header":      "Authorization: Bearer <client-api-key>",
			"tokenSource": "Read the token from ACCESSGATE_API_TOKEN. Never print, persist, commit, or echo it.",
		},
		"endpoints": map[string]any{
			"public":        []string{"GET /v1/informer", "GET /v1/informer/agent-contract", "GET /v1/informer/process", "GET /v1/informer/schema", "GET /v1/informer/errors"},
			"authenticated": []string{"GET /v1/targets", "POST /v1/leases", "POST /v1/access-cases/{caseId}/claim", "GET /v1/leases/{leaseId}", "POST /v1/leases/{leaseId}/revoke"},
		},
		"accessProfiles": []map[string]any{
			{"name": "normal", "linuxUser": "accessgate-normal", "sudo": false, "description": "Managed AccessGate user without sudo."},
			{"name": "elevated", "linuxUser": "accessgate-elevated", "sudo": "passwordless", "description": "Managed AccessGate user with passwordless sudo through the accessgate-elevated group."},
		},
		"flow": []string{
			"Call GET /v1/targets with the bearer token and choose a target whose state is active, agentStatus is verified, and allowedAccessProfiles contains the needed profile.",
			"Call POST /v1/leases with target, role, accessProfile, timeframe, and reason.",
			"For state=active, store privateKey exactly once in a temporary key file with restrictive permissions.",
			"Connect with ssh -i <keyfile> <linuxUser>@<host> using the linuxUser and host returned by the lease response.",
			"Retry SSH for the propagation window because the AG-Agent applies desired state asynchronously.",
			"Always revoke the lease with POST /v1/leases/{leaseId}/revoke in cleanup/finally, even after failures.",
		},
		"schemas": agentContractSchemas(),
		"examples": map[string]any{
			"createNormalLease": map[string]any{
				"target": "server-a", "role": "normal", "accessProfile": "normal",
				"timeframe": map[string]any{"type": "duration", "seconds": 900},
				"reason":    "Investigate service health and logs",
			},
			"createElevatedLease": map[string]any{
				"target": "server-a", "role": "normal", "accessProfile": "elevated",
				"timeframe": map[string]any{"type": "duration", "seconds": 900},
				"reason":    "Restart a failed service after inspection",
			},
			"activeLeaseResponse": map[string]any{
				"leaseId": "lease_example", "version": 1, "generation": 1, "state": "active", "approvalRequired": false,
				"target": "server-a", "host": "10.0.0.11", "role": "normal", "accessProfile": "normal", "linuxUser": "accessgate-normal",
				"expiresAt": "2026-07-09T17:00:00Z", "keyDelivery": "generated_once", "keyFingerprint": "SHA256:...", "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----...",
			},
			"revokeLease": map[string]any{"method": "POST", "path": "/v1/leases/{leaseId}/revoke"},
		},
		"ssh": map[string]any{
			"commandTemplate":    "ssh -i <temporary-private-key-file> <linuxUser>@<host>",
			"privateKeyHandling": []string{"The privateKey is returned exactly once.", "Write it only to a temporary file with restrictive permissions.", "Delete the file after use.", "Never print or log privateKey."},
			"propagation":        map[string]any{"expectedSeconds": 5, "retry": map[string]any{"attempts": 6, "delaySeconds": 2, "retryOn": []string{"Permission denied", "Connection refused", "Connection timed out"}}},
		},
		"cleanup": map[string]any{
			"required":   true,
			"rule":       "Always call POST /v1/leases/{leaseId}/revoke in finally/cleanup as soon as access is no longer needed.",
			"alsoDelete": []string{"temporary private key file", "derived SSH config snippets or temp known-host artifacts created by the agent"},
		},
		"errors": agentContractErrors(),
	})
}

func (s *Server) agentBinary(w http.ResponseWriter, r *http.Request) {
	target, ok := s.requireAgent(w, r, "")
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/agent-binaries/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not_found", "agent binary not found")
		return
	}
	goarch := parts[0]
	if goarch != "arm64" && goarch != "amd64" {
		writeError(w, http.StatusNotFound, "unsupported_arch", "unsupported agent architecture")
		return
	}
	binary, err := s.agentBinaryForGoArch(goarch)
	if err != nil {
		writeError(w, http.StatusNotFound, "binary_not_found", err.Error())
		return
	}
	sum, size, err := fileSHA256(binary)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "binary_hash_failed", err.Error())
		return
	}
	if len(parts) == 2 && parts[1] == "meta" {
		writeEncryptedJSON(w, http.StatusOK, target.AgentSecret, map[string]any{
			"version": version, "os": "linux", "arch": goarch, "sha256": sum, "size": size,
			"url": "/v1/agent-binaries/" + goarch,
		})
		return
	}
	if len(parts) == 1 {
		b, err := os.ReadFile(binary)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "binary_read_failed", err.Error())
			return
		}
		w.Header().Set("X-AccessGate-Agent-Version", version)
		w.Header().Set("X-AccessGate-Agent-SHA256", sum)
		writeEncryptedBytes(w, http.StatusOK, target.AgentSecret, b)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "agent binary endpoint not found")
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireClient(w, r); !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"targets": publicTargets(s.state.Targets)})
}

func publicTargets(targets []Target) []Target {
	out := make([]Target, len(targets))
	copy(out, targets)
	for i := range out {
		out[i].AgentSecret = ""
	}
	return out
}

func (s *Server) leases(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := s.requireClient(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req createLeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.Timeframe.Type == "" && req.TTLSeconds > 0 {
		req.Timeframe = Timeframe{Type: "duration", Seconds: req.TTLSeconds}
	}
	lease, privateKey, err := s.createLease(apiKey, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "policy_denied", err.Error())
		return
	}
	resp := leaseResponse(lease)
	if privateKey != "" {
		resp["privateKey"] = privateKey
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) createLease(apiKey APIKey, req createLeaseRequest) (Lease, string, error) {
	if req.Role == "" {
		req.Role = "normal"
	}
	profile, linuxUser, err := resolveAccessProfile(req.AccessProfile, req.LinuxUser)
	if err != nil {
		return Lease{}, "", err
	}
	if req.Target == "" || req.Role == "" || profile == "" || req.Reason == "" {
		return Lease{}, "", errors.New("target, role, accessProfile and reason are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.findTarget(req.Target)
	if !ok {
		return Lease{}, "", errors.New("unknown target")
	}
	if len(target.AllowedProfiles) == 0 {
		target.AllowedProfiles = defaultAccessProfiles()
	}
	if !contains(target.AllowedRoles, req.Role) || !contains(target.AllowedProfiles, profile) {
		return Lease{}, "", errors.New("role or accessProfile not allowed for target")
	}
	if target.State != "active" || target.AgentStatus != "verified" {
		return Lease{}, "", errors.New("target agent is not active")
	}
	now := time.Now().UTC()
	lease := Lease{
		ID: "lease_" + token(16), Version: 1, Generation: 1, State: "active",
		RequesterID: apiKey.RequesterID, Target: target.ID, Host: target.Host, Role: req.Role, AccessProfile: profile, LinuxUser: linuxUser,
		KeyDelivery: "generated_once", Reason: req.Reason, Timeframe: req.Timeframe, Restrictions: normalizeRestrictions(req.Restrictions), CreatedAt: now,
	}
	var privateKey string
	if req.Role == "normal" {
		if req.Timeframe.Type != "duration" || req.Timeframe.Seconds <= 0 {
			return Lease{}, "", errors.New("normal access requires duration timeframe")
		}
		if req.Timeframe.Seconds > target.MaxTTLSeconds || req.Timeframe.Seconds > 3600 {
			return Lease{}, "", errors.New("normal access ttl exceeds 1 hour")
		}
		exp := now.Add(time.Duration(req.Timeframe.Seconds) * time.Second)
		lease.ExpiresAt = &exp
		pub, priv, fp, err := generateSSHKey(lease.ID)
		if err != nil {
			return Lease{}, "", err
		}
		lease.PublicKey, lease.KeyFingerprint, privateKey = pub, fp, priv
	} else if req.Role == "serviceuser" && req.Timeframe.Type == "unlimited" {
		lease.State = "pending_approval"
		lease.CaseID = "case_" + token(16)
	} else {
		return Lease{}, "", errors.New("unsupported role/timeframe combination")
	}
	s.state.Leases = append(s.state.Leases, lease)
	s.auditLocked("lease.created", apiKey.RequesterID, lease.ID+" "+lease.State)
	return lease, privateKey, s.saveLocked()
}

func (s *Server) leaseAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/leases/"), "/")
	if len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost {
		sess, ok := s.requireOps(w, r)
		if !ok {
			return
		}
		lease, ok := s.approveLease(parts[0], sess.Operator)
		if !ok {
			writeError(w, http.StatusConflict, "case_not_approvable", "lease is not pending approval")
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			writeJSON(w, http.StatusOK, leaseResponse(lease))
			return
		}
		http.Redirect(w, r, "/ops", http.StatusFound)
		return
	}
	if _, ok := s.requireClient(w, r); !ok {
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.mu.Lock()
		s.expireLeasesLocked(time.Now().UTC())
		_ = s.saveLocked()
		defer s.mu.Unlock()
		for _, lease := range s.state.Leases {
			if lease.ID == parts[0] {
				writeJSON(w, http.StatusOK, leaseResponse(lease))
				return
			}
		}
		writeError(w, http.StatusNotFound, "not_found", "lease not found")
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.state.Leases {
			if s.state.Leases[i].ID == parts[0] {
				lease := s.state.Leases[i]
				lease.State = "revoked"
				lease.Version++
				lease.Generation++
				s.archiveLeaseLocked(lease)
				s.state.Leases = append(s.state.Leases[:i], s.state.Leases[i+1:]...)
				s.auditLocked("lease.revoked", "api", parts[0])
				_ = s.saveLocked()
				go s.pushLeaseRevoke(lease)
				writeJSON(w, http.StatusOK, leaseResponse(lease))
				return
			}
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "lease not found")
}

func (s *Server) agentDesiredState(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/agents/"), "/")
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not_found", "desired-state endpoint not found")
		return
	}
	agentID := parts[0]
	if parts[1] == "events" {
		s.agentEvent(w, r, agentID)
		return
	}
	if parts[1] != "desired-state" {
		writeError(w, http.StatusNotFound, "not_found", "agent endpoint not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	target, ok := s.requireAgent(w, r, agentID)
	if !ok {
		return
	}
	s.mu.Lock()
	s.expireLeasesLocked(time.Now().UTC())
	_ = s.saveLocked()
	leases := []AgentLease{}
	commands := []AgentCommand{}
	version := 0
	for _, lease := range s.state.Leases {
		if lease.Target != agentID || lease.State != "active" || lease.PublicKey == "" {
			continue
		}
		if lease.Version > version {
			version = lease.Version
		}
		leases = append(leases, AgentLease{
			LeaseID: lease.ID, Version: lease.Version, Generation: lease.Generation, State: lease.State,
			AccessProfile: lease.AccessProfile, LinuxUser: lease.LinuxUser, PublicKey: lease.PublicKey, ExpiresAt: lease.ExpiresAt, Restrictions: lease.Restrictions,
		})
	}
	if (target.RemovalMode == "retire" || target.RemovalMode == "kill") && target.RemovalCommandID != "" && target.RemovalDeadline != nil && time.Now().UTC().Before(*target.RemovalDeadline) {
		action := "retire"
		if target.RemovalMode == "kill" {
			action = "tombstone"
		}
		issued := time.Now().UTC()
		if target.RemovalRequested != nil {
			issued = *target.RemovalRequested
		}
		commands = append(commands, AgentCommand{
			CommandID: target.RemovalCommandID, Action: action, Reason: target.RemovalReason,
			AgentID: target.ID, Generation: 1, IssuedAt: issued, ExpiresAt: *target.RemovalDeadline,
		})
	}
	s.mu.Unlock()
	writeEncryptedJSON(w, http.StatusOK, target.AgentSecret, desiredStateResponse{AgentID: agentID, DesiredStateVersion: version, Leases: leases, Commands: commands})
}

func (s *Server) agentEvent(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if _, ok := s.requireAgent(w, r, agentID); !ok {
		return
	}
	var evt struct {
		CommandID string `json:"commandId"`
		Type      string `json:"type"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLocked("agent."+evt.Type, agentID, evt.CommandID+" "+evt.Message)
	if strings.HasSuffix(evt.Type, ".completed") {
		s.finalizeTargetRemovalLocked(agentID, evt.Type)
	}
	if err := s.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "state_save_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "accepted"})
}

func (s *Server) pushLeaseRevoke(lease Lease) {
	target, ok := s.targetByID(lease.Target)
	if !ok || target.AgentSecret == "" {
		s.mu.Lock()
		s.auditLocked("lease.revoke_push.skipped", "accessgate", lease.ID+" target unavailable")
		_ = s.saveLocked()
		s.mu.Unlock()
		return
	}
	body, err := json.Marshal(map[string]any{
		"leaseId": lease.ID, "accessProfile": lease.AccessProfile, "linuxUser": lease.LinuxUser, "version": lease.Version,
		"generation": lease.Generation, "mode": "rapid_revoke",
	})
	if err != nil {
		return
	}
	url := fmt.Sprintf("http://%s:9187/v1/agent/leases/%s/revoke-notify", target.Host, lease.ID)
	req, err := newAgentRequest(http.MethodPost, url, body, target.ID, target.AgentSecret)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.auditLocked("lease.revoke_push.failed", "accessgate", lease.ID+" "+err.Error())
		_ = s.saveLocked()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.auditLocked("lease.revoke_push.failed", "accessgate", fmt.Sprintf("%s status=%d", lease.ID, resp.StatusCode))
		_ = s.saveLocked()
		return
	}
	s.auditLocked("lease.revoke_push.sent", "accessgate", lease.ID+" "+target.ID)
	_ = s.saveLocked()
}

func (s *Server) claimCase(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := s.requireClient(w, r)
	if !ok {
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/claim") || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not_found", "claim endpoint not found")
		return
	}
	caseID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/access-cases/"), "/claim")
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Leases {
		l := &s.state.Leases[i]
		if l.CaseID != caseID || l.RequesterID != apiKey.RequesterID {
			continue
		}
		if l.State == "pending_approval" {
			writeJSON(w, http.StatusAccepted, map[string]string{"caseId": caseID, "state": "pending_approval", "status": "Pending approval"})
			return
		}
		if l.State != "approved" {
			writeError(w, http.StatusConflict, "case_not_claimable", "case is not claimable")
			return
		}
		pub, priv, fp, err := generateSSHKey(l.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "key_generation_failed", err.Error())
			return
		}
		l.PublicKey, l.KeyFingerprint = pub, fp
		l.State = "active"
		l.Version++
		s.auditLocked("lease.claimed", apiKey.RequesterID, l.ID)
		_ = s.saveLocked()
		resp := leaseResponse(*l)
		resp["privateKey"] = priv
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeError(w, http.StatusNotFound, "case_not_found", "case not found")
}

func (s *Server) adminAPIKeys(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireOps(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	var req struct {
		DisplayName   string   `json:"displayName"`
		RequesterType string   `json:"requesterType"`
		Owner         string   `json:"owner"`
		PolicyGroups  []string `json:"policyGroups"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_form", err.Error())
			return
		}
		req.DisplayName = r.FormValue("displayName")
		req.RequesterType = r.FormValue("requesterType")
		req.Owner = r.FormValue("owner")
		req.PolicyGroups = splitCSV(r.FormValue("policyGroups"))
	}
	if req.DisplayName == "" || req.RequesterType == "" {
		writeError(w, http.StatusBadRequest, "invalid_api_key", "displayName and requesterType are required")
		return
	}
	full := "agk_live_" + token(24)
	key := APIKey{ID: "agkey_" + token(12), RequesterID: "req_" + token(12), DisplayName: req.DisplayName, RequesterType: req.RequesterType, Hash: hashSecret(full), PolicyGroups: req.PolicyGroups, CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	s.state.APIKeys = append(s.state.APIKeys, key)
	s.auditLocked("api_key.created", sess.Operator, key.ID)
	_ = s.saveLocked()
	s.mu.Unlock()
	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusCreated, map[string]any{"apiKeyId": key.ID, "requesterId": key.RequesterID, "displayName": key.DisplayName, "requesterType": key.RequesterType, "apiKey": full, "shownOnce": true})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>AccessGate API Key</title><style>body{background:#101214;color:#e8ecef;font:14px system-ui;padding:24px}code{display:block;white-space:pre-wrap;background:#161a1e;padding:14px;border:1px solid #2b3035}</style></head><body><h1>API Key</h1><code>%s</code><p><a href="/ops/api-keys">Back</a></p></body></html>`, template.HTMLEscapeString(full))
}

func (s *Server) adminAPIKeyAction(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireOps(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/admin/api-keys/"), "/")
	if len(parts) != 2 || parts[1] != "revoke" || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not_found", "api key action not found")
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.APIKeys {
		if s.state.APIKeys[i].ID == parts[0] {
			key := s.state.APIKeys[i]
			key.RevokedAt = &now
			s.archiveAPIKeyLocked(key)
			s.state.APIKeys = append(s.state.APIKeys[:i], s.state.APIKeys[i+1:]...)
			s.auditLocked("api_key.revoked", sess.Operator, parts[0])
			if err := s.saveLocked(); err != nil {
				writeError(w, http.StatusInternalServerError, "state_save_failed", err.Error())
				return
			}
			http.Redirect(w, r, "/ops/api-keys", http.StatusFound)
			return
		}
	}
	writeError(w, http.StatusNotFound, "api_key_not_found", "api key not found")
}

func (s *Server) adminTargets(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireOps(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}

	var req struct {
		ID                            string   `json:"target"`
		DisplayName                   string   `json:"displayName"`
		Host                          string   `json:"host"`
		SSHPort                       int      `json:"sshPort"`
		AllowedRoles                  []string `json:"allowedRoles"`
		AllowedProfiles               []string `json:"allowedAccessProfiles"`
		MaxTTLSeconds                 int      `json:"maxTtlSeconds"`
		BootstrapUser                 string   `json:"bootstrapUser"`
		BootstrapAuthMethod           string   `json:"bootstrapAuthMethod"`
		BootstrapPassword             string   `json:"bootstrapPassword"`
		BootstrapPrivateKey           string   `json:"bootstrapPrivateKey"`
		BootstrapPrivateKeyPassphrase string   `json:"bootstrapPrivateKeyPassphrase"`
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_form", err.Error())
			return
		}
		req.ID = r.FormValue("target")
		req.DisplayName = r.FormValue("displayName")
		req.Host = r.FormValue("host")
		req.SSHPort, _ = strconv.Atoi(r.FormValue("sshPort"))
		req.AllowedRoles = splitCSV(r.FormValue("allowedRoles"))
		req.AllowedProfiles = splitCSV(r.FormValue("allowedAccessProfiles"))
		req.MaxTTLSeconds, _ = strconv.Atoi(r.FormValue("maxTtlSeconds"))
		req.BootstrapUser = r.FormValue("bootstrapUser")
		req.BootstrapAuthMethod = r.FormValue("bootstrapAuthMethod")
		req.BootstrapPassword = r.FormValue("bootstrapPassword")
		req.BootstrapPrivateKey = r.FormValue("bootstrapPrivateKey")
		req.BootstrapPrivateKeyPassphrase = r.FormValue("bootstrapPrivateKeyPassphrase")
	}

	target, err := normalizeTarget(req.ID, req.DisplayName, req.Host, req.SSHPort, req.AllowedRoles, req.AllowedProfiles, req.MaxTTLSeconds)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_target", err.Error())
		return
	}
	bootstrap := BootstrapCredentials{
		User: req.BootstrapUser, AuthMethod: req.BootstrapAuthMethod, Password: req.BootstrapPassword,
		PrivateKey: req.BootstrapPrivateKey, PrivateKeyPassphrase: req.BootstrapPrivateKeyPassphrase,
	}
	if err := bootstrap.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_bootstrap", err.Error())
		return
	}
	target.State = "pending_bootstrap"
	target.AgentStatus = "unverified"
	target.BootstrapStatus = "queued"
	target.AgentSecret = "agsec_" + token(32)

	s.mu.Lock()
	updatedExisting := false
	for i := range s.state.Targets {
		if s.state.Targets[i].ID == target.ID {
			if s.state.Targets[i].AgentSecret != "" {
				target.AgentSecret = s.state.Targets[i].AgentSecret
			}
			s.state.Targets[i].DisplayName = target.DisplayName
			s.state.Targets[i].Host = target.Host
			s.state.Targets[i].SSHPort = target.SSHPort
			s.state.Targets[i].AgentSecret = target.AgentSecret
			s.state.Targets[i].AllowedRoles = target.AllowedRoles
			s.state.Targets[i].AllowedProfiles = target.AllowedProfiles
			s.state.Targets[i].AllowedLinuxUsers = nil
			s.state.Targets[i].MaxTTLSeconds = target.MaxTTLSeconds
			s.state.Targets[i].State = "pending_bootstrap"
			s.state.Targets[i].AgentStatus = "unverified"
			s.state.Targets[i].BootstrapStatus = "queued"
			s.state.Targets[i].BootstrapMessage = ""
			updatedExisting = true
			break
		}
	}
	for _, existing := range s.state.Targets {
		if existing.ID != target.ID && existing.Host == target.Host {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "target_host_exists", "target host already exists")
			return
		}
	}
	if !updatedExisting {
		s.state.Targets = append(s.state.Targets, target)
		s.auditLocked("target.created", sess.Operator, target.ID+" "+target.Host)
	} else {
		s.auditLocked("target.bootstrap.requested", sess.Operator, target.ID+" "+target.Host)
	}
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_save_failed", err.Error())
		return
	}
	go s.bootstrapTarget(target.ID, bootstrap)

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusCreated, target)
		return
	}
	http.Redirect(w, r, "/ops", http.StatusFound)
}

func (s *Server) adminTargetAction(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireOps(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/admin/targets/"), "/")
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not_found", "target action not found")
		return
	}
	if parts[1] != "retire" && parts[1] != "kill" && parts[1] != "delete" {
		writeError(w, http.StatusNotFound, "not_found", "target action not found")
		return
	}
	targetID := parts[0]
	s.mu.Lock()
	for _, lease := range s.state.Leases {
		if lease.Target == targetID && (lease.State == "active" || lease.State == "pending_approval" || lease.State == "approved") {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "target_in_use", "target has active or pending leases")
			return
		}
	}
	for i := range s.state.Targets {
		target := s.state.Targets[i]
		if target.ID == targetID {
			mode := parts[1]
			if mode == "delete" {
				mode = "retire"
			}
			now := time.Now().UTC()
			grace := 60 * time.Second
			state := "retiring"
			if mode == "kill" {
				grace = 10 * time.Second
				state = "tombstone_sent"
			}
			deadline := now.Add(grace)
			s.state.Targets[i].State = state
			s.state.Targets[i].AgentStatus = state
			s.state.Targets[i].RemovalMode = mode
			s.state.Targets[i].RemovalCommandID = "cmd_" + token(16)
			s.state.Targets[i].RemovalReason = "operator=" + sess.Operator
			s.state.Targets[i].RemovalRequested = &now
			s.state.Targets[i].RemovalDeadline = &deadline
			s.auditLocked("target."+mode+".requested", sess.Operator, target.ID+" "+target.Host)
			if err := s.saveLocked(); err != nil {
				s.mu.Unlock()
				writeError(w, http.StatusInternalServerError, "state_save_failed", err.Error())
				return
			}
			s.mu.Unlock()
			go s.finalizeTargetRemovalAfter(targetID, mode, grace+2*time.Second)
			if strings.Contains(r.Header.Get("Accept"), "application/json") {
				writeJSON(w, http.StatusOK, map[string]string{"state": state, "target": targetID, "mode": mode})
				return
			}
			http.Redirect(w, r, "/ops/targets", http.StatusFound)
			return
		}
	}
	s.mu.Unlock()
	writeError(w, http.StatusNotFound, "target_not_found", "target not found")
}

func (s *Server) finalizeTargetRemovalAfter(targetID, mode string, delay time.Duration) {
	time.Sleep(delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, target := range s.state.Targets {
		if target.ID == targetID && target.RemovalMode == mode {
			s.finalizeTargetRemovalLocked(targetID, "timeout")
			_ = s.saveLocked()
			return
		}
	}
}

func (s *Server) finalizeTargetRemovalLocked(targetID, result string) {
	for i, target := range s.state.Targets {
		if target.ID != targetID {
			continue
		}
		s.auditLocked("target.identity.revoked", "accessgate", target.ID+" "+result)
		s.auditLocked("target.removed", "accessgate", target.ID+" "+target.RemovalMode)
		s.state.Targets = append(s.state.Targets[:i], s.state.Targets[i+1:]...)
		return
	}
}

func (s *Server) createOpsLink(operator string, ttl time.Duration, baseURL string) (string, error) {
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	if baseURL == "" {
		baseURL = env("ACCESSGATE_PUBLIC_URL", "http://127.0.0.1:8080")
	}
	raw := "agops_" + token(32)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.OpsLinks = append(s.state.OpsLinks, OpsLink{TokenHash: hashSecret(raw), Operator: operator, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	s.auditLocked("ops_link.created", operator, "ttl="+ttl.String())
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return strings.TrimRight(baseURL, "/") + "/ops/" + raw, nil
}

func createOpsLinkViaRunningServer(operator string, ttl time.Duration, baseURL string) (string, bool, error) {
	key := strings.TrimSpace(os.Getenv("ACCESSGATE_BOOTSTRAP_API_KEY"))
	if key == "" {
		return "", false, nil
	}
	addr := env("ACCESSGATE_ADDR", ":8080")
	localURL := "http://127.0.0.1:8080/v1/internal/ops-link"
	if strings.HasPrefix(addr, ":") {
		localURL = "http://127.0.0.1" + addr + "/v1/internal/ops-link"
	} else if strings.Contains(addr, ":") {
		localURL = "http://" + addr + "/v1/internal/ops-link"
	}
	body, err := json.Marshal(map[string]any{
		"operator":   operator,
		"ttlSeconds": int(ttl.Seconds()),
		"baseURL":    baseURL,
	})
	if err != nil {
		return "", true, err
	}
	req, err := http.NewRequest(http.MethodPost, localURL, bytes.NewReader(body))
	if err != nil {
		return "", true, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", true, fmt.Errorf("running server ops link request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", true, err
	}
	if out.Link == "" {
		return "", true, errors.New("running server returned empty ops link")
	}
	return out.Link, true, nil
}

func (s *Server) internalOpsLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	key := strings.TrimSpace(os.Getenv("ACCESSGATE_BOOTSTRAP_API_KEY"))
	if key == "" || strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != key {
		writeError(w, http.StatusUnauthorized, "unauthorized", "bootstrap authorization required")
		return
	}
	var req struct {
		Operator   string `json:"operator"`
		TTLSeconds int    `json:"ttlSeconds"`
		BaseURL    string `json:"baseURL"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if strings.TrimSpace(req.Operator) == "" {
		req.Operator = "operator"
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	link, err := s.createOpsLink(req.Operator, ttl, req.BaseURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ops_link_create_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"link": link})
}

func (s *Server) clearOpsAccess(operator string) (int, error) {
	now := time.Now().UTC()
	count := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.OpsLinks {
		if s.state.OpsLinks[i].ConsumedAt == nil && now.Before(s.state.OpsLinks[i].ExpiresAt) {
			s.state.OpsLinks[i].ConsumedAt = &now
			count++
		}
	}
	for i := range s.state.OpsSessions {
		if now.Before(s.state.OpsSessions[i].ExpiresAt) {
			s.state.OpsSessions[i].ExpiresAt = now
			count++
		}
	}
	s.auditLocked("ops_access.cleared", operator, fmt.Sprintf("count=%d", count))
	return count, s.saveLocked()
}

func (s *Server) consumeOpsLink(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.URL.Path, "/ops/")
	if !strings.HasPrefix(raw, "agops_") || strings.Contains(raw, "/") {
		s.opsPanel(w, r)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "state_load_failed", err.Error())
		return
	}
	hash := hashSecret(raw)
	for i := range s.state.OpsLinks {
		l := &s.state.OpsLinks[i]
		if l.TokenHash != hash {
			continue
		}
		if l.ConsumedAt != nil {
			if c, err := r.Cookie("ag_ops_session"); err == nil && c.Value == l.SessionID && s.opsSessionActiveLocked(c.Value, now) {
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, "/ops/leases", http.StatusSeeOther)
				return
			}
			break
		}
		if now.Before(l.ExpiresAt) {
			l.ConsumedAt = &now
			sess := OpsSession{ID: "ops_sess_" + token(24), Operator: l.Operator, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			l.SessionID = sess.ID
			s.state.OpsSessions = append(s.state.OpsSessions, sess)
			s.auditLocked("ops_session.created", l.Operator, sess.ID)
			_ = s.saveLocked()
			http.SetCookie(w, &http.Cookie{Name: "ag_ops_session", Value: sess.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: sess.ExpiresAt, MaxAge: int(time.Until(sess.ExpiresAt).Seconds())})
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/ops/leases", http.StatusSeeOther)
			return
		}
	}
	s.opsInactive(w)
}

func (s *Server) opsSessionActiveLocked(sessionID string, now time.Time) bool {
	if sessionID == "" {
		return false
	}
	for _, sess := range s.state.OpsSessions {
		if sess.ID == sessionID && now.Before(sess.ExpiresAt) {
			return true
		}
	}
	return false
}

func (s *Server) opsPanel(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireOps(w, r)
	if !ok {
		return
	}
	page := strings.TrimPrefix(r.URL.Path, "/ops")
	if page == "" || page == "/" {
		page = "dashboard"
	} else {
		page = strings.TrimPrefix(page, "/")
	}
	autoRefresh := r.URL.Query().Get("refresh") == "1"
	s.mu.Lock()
	s.expireLeasesLocked(time.Now().UTC())
	_ = s.saveLocked()
	data := struct {
		Session       OpsSession
		Leases        []Lease
		LeaseHistory  []Lease
		Targets       []Target
		APIKeys       []APIKey
		APIKeyHistory []APIKey
		Events        []AuditEvent
		Page          string
		AutoRefresh   bool
	}{
		Session:       sess,
		Leases:        append([]Lease(nil), s.state.Leases...),
		LeaseHistory:  append([]Lease(nil), s.state.LeaseHistory...),
		Targets:       append([]Target(nil), s.state.Targets...),
		APIKeys:       append([]APIKey(nil), s.state.APIKeys...),
		APIKeyHistory: append([]APIKey(nil), s.state.APIKeyHistory...),
		Events:        append([]AuditEvent(nil), s.state.Events...),
		Page:          page,
		AutoRefresh:   autoRefresh,
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = opsTemplate.Execute(w, data)
}

func (s *Server) opsStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireOps(w, r); !ok {
		return
	}
	s.mu.Lock()
	s.expireLeasesLocked(time.Now().UTC())
	_ = s.saveLocked()
	targets := make([]map[string]any, 0, len(s.state.Targets))
	for _, t := range s.state.Targets {
		targets = append(targets, map[string]any{
			"id": t.ID, "state": t.State, "agentStatus": t.AgentStatus,
			"bootstrapStatus": t.BootstrapStatus, "bootstrapMessage": t.BootstrapMessage,
		})
	}
	leases := make([]map[string]any, 0, len(s.state.Leases))
	for _, l := range s.state.Leases {
		ttl := "unlimited"
		if l.ExpiresAt != nil {
			ttl = "expired"
			if seconds := int64(time.Until(*l.ExpiresAt).Seconds()); seconds > 0 {
				ttl = strconv.FormatInt(seconds, 10) + "s"
			}
		}
		leases = append(leases, map[string]any{"id": l.ID, "state": l.State, "ttl": ttl})
	}
	resp := map[string]any{
		"counts":  map[string]int{"leases": len(s.state.Leases), "targets": len(s.state.Targets), "apiKeys": len(s.state.APIKeys)},
		"targets": targets,
		"leases":  leases,
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) expireLeasesLocked(now time.Time) {
	active := s.state.Leases[:0]
	for i := range s.state.Leases {
		lease := s.state.Leases[i]
		if lease.State == "expired" {
			s.archiveLeaseLocked(lease)
			continue
		}
		if lease.State == "active" && lease.ExpiresAt != nil && !now.Before(*lease.ExpiresAt) {
			lease.State = "expired"
			lease.Version++
			lease.Generation++
			s.archiveLeaseLocked(lease)
			s.auditLocked("lease.expired", "accessgate", lease.ID)
			continue
		}
		active = append(active, lease)
	}
	s.state.Leases = active
}

func (s *Server) archiveLeaseLocked(lease Lease) {
	for i := range s.state.LeaseHistory {
		if s.state.LeaseHistory[i].ID == lease.ID {
			s.state.LeaseHistory[i] = lease
			return
		}
	}
	s.state.LeaseHistory = append([]Lease{lease}, s.state.LeaseHistory...)
}

func (s *Server) archiveAPIKeyLocked(key APIKey) {
	for i := range s.state.APIKeyHistory {
		if s.state.APIKeyHistory[i].ID == key.ID {
			s.state.APIKeyHistory[i] = key
			return
		}
	}
	s.state.APIKeyHistory = append([]APIKey{key}, s.state.APIKeyHistory...)
}

func (s *Server) approveLease(leaseID, operator string) (Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for i := range s.state.Leases {
		l := &s.state.Leases[i]
		if l.ID == leaseID && l.State == "pending_approval" {
			l.State = "approved"
			l.Version++
			l.ApprovedAt = &now
			l.ApprovedBy = operator
			s.auditLocked("lease.approved", operator, leaseID)
			_ = s.saveLocked()
			return *l, true
		}
	}
	return Lease{}, false
}

func (s *Server) bootstrapTarget(targetID string, creds BootstrapCredentials) {
	s.setTargetBootstrap(targetID, "running", "unverified", "connecting", "")
	target, ok := s.targetByID(targetID)
	if !ok {
		return
	}
	if err := s.installAgentOverSSH(target, creds); err != nil {
		s.setTargetBootstrap(targetID, "bootstrap_failed", "unverified", "failed", err.Error())
		return
	}
	s.setTargetBootstrap(targetID, "active", "verified", "complete", "AG-Agent installed and systemd service is active")
}

func (s *Server) targetByID(targetID string) (Target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, target := range s.state.Targets {
		if target.ID == targetID {
			return target, true
		}
	}
	return Target{}, false
}

func (s *Server) setTargetBootstrap(targetID, state, agentStatus, bootstrapStatus, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Targets {
		if s.state.Targets[i].ID == targetID {
			s.state.Targets[i].State = state
			s.state.Targets[i].AgentStatus = agentStatus
			s.state.Targets[i].BootstrapStatus = bootstrapStatus
			s.state.Targets[i].BootstrapMessage = message
			s.auditLocked("target.bootstrap."+bootstrapStatus, "bootstrap", targetID+" "+message)
			_ = s.saveLocked()
			return
		}
	}
}

func (s *Server) installAgentOverSSH(target Target, creds BootstrapCredentials) error {
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, target.SSHPort), sshConfig(creds))
	if err != nil {
		return fmt.Errorf("ssh connect failed: %w", err)
	}
	defer client.Close()

	arch, err := detectTargetArch(client)
	if err != nil {
		return fmt.Errorf("architecture detection failed: %w", err)
	}
	agentBinary, err := s.agentBinaryForArch(strings.TrimSpace(arch))
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(agentBinary)
	if err != nil {
		return err
	}
	if err := uploadSSHFile(client, "/tmp/accessgate-agent.new", binary); err != nil {
		return fmt.Errorf("binary upload failed: %w", err)
	}
	if target.AgentSecret == "" {
		return errors.New("target agent secret is missing")
	}
	if err := uploadSSHFile(client, "/tmp/accessgate-agent.secret", []byte(target.AgentSecret+"\n")); err != nil {
		return fmt.Errorf("agent secret upload failed: %w", err)
	}

	serverURL := env("ACCESSGATE_AGENT_SERVER_URL", env("ACCESSGATE_PUBLIC_URL", "https://accessgate.example.com"))
	unit := `[Unit]
Description=AccessGate AG-Agent
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/accessgate-agent -agent -agent-id ` + shellUnitArg(target.ID) + ` -server-url ` + shellUnitArg(serverURL) + ` -agent-secret-file /etc/accessgate-agent/agent.secret -agent-addr 0.0.0.0:9187 -agent-auto-update=true
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
`
	if err := uploadSSHFile(client, "/tmp/accessgate-agent.service", []byte(unit)); err != nil {
		return fmt.Errorf("unit upload failed: %w", err)
	}

	script := `set -eu
install -o root -g root -m 0755 /tmp/accessgate-agent.new /usr/local/bin/accessgate-agent
install -d -o root -g root -m 0700 /etc/accessgate-agent
install -d -o root -g root -m 0700 /var/lib/accessgate-agent
install -d -o root -g root -m 0750 /var/log/accessgate-agent
install -o root -g root -m 0600 /tmp/accessgate-agent.secret /etc/accessgate-agent/agent.secret
install -o root -g root -m 0644 /tmp/accessgate-agent.service /etc/systemd/system/accessgate-agent.service
getent group accessgate-normal >/dev/null || groupadd --system accessgate-normal
getent group accessgate-elevated >/dev/null || groupadd --system accessgate-elevated
id -u accessgate-normal >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/accessgate-normal --shell /bin/bash --gid accessgate-normal accessgate-normal
id -u accessgate-elevated >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/accessgate-elevated --shell /bin/bash --gid accessgate-elevated accessgate-elevated
usermod -a -G accessgate-normal accessgate-normal
usermod -a -G accessgate-elevated accessgate-elevated
printf '%s\n' '%accessgate-elevated ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/accessgate-elevated
chmod 0440 /etc/sudoers.d/accessgate-elevated
visudo -cf /etc/sudoers.d/accessgate-elevated
grep -q '[[:space:]]accessgate\.example\.com' /etc/hosts || printf '%s\n' '10.0.0.10 accessgate.example.com' >> /etc/hosts
mkdir -p /etc/ssh/sshd_config.d
printf '%s\n' 'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys_accessgate' > /etc/ssh/sshd_config.d/99-accessgate.conf
sshd -t
systemctl daemon-reload
systemctl enable accessgate-agent
systemctl restart accessgate-agent
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
for i in $(seq 1 20); do
	if systemctl is-active --quiet accessgate-agent; then
		exit 0
	fi
	sleep 1
done
systemctl status accessgate-agent --no-pager -l
exit 3
`
	if err := runPrivilegedSSH(client, creds, script); err != nil {
		return fmt.Errorf("agent install failed: %w", err)
	}
	return nil
}

func detectTargetArch(client *ssh.Client) (string, error) {
	var lastErr error
	for _, cmd := range []string{"uname -m", "/bin/uname -m", "dpkg --print-architecture"} {
		out, err := runSSHOutput(client, cmd)
		if err != nil {
			lastErr = err
			continue
		}
		out = strings.TrimSpace(out)
		if out != "" {
			return out, nil
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("target architecture detection returned empty output")
}

func (s *Server) agentBinaryForArch(unameArch string) (string, error) {
	var goarch string
	switch unameArch {
	case "x86_64", "amd64":
		goarch = "amd64"
	case "aarch64", "arm64", "arm64/v8":
		goarch = "arm64"
	default:
		return "", fmt.Errorf("unsupported target architecture %q", unameArch)
	}
	return s.agentBinaryForGoArch(goarch)
}

func (s *Server) agentBinaryForGoArch(goarch string) (string, error) {
	candidates := []string{
		filepath.Join(filepath.Dir(mustExecutable()), "agents", "accessgate-agent-linux-"+goarch),
		filepath.Join(s.dataDir, "agents", "accessgate-agent-linux-"+goarch),
		"/agents/accessgate-agent-linux-" + goarch,
	}
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("agent binary for %s not found", goarch)
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func mustExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return "/accessgate"
	}
	return exe
}

func sshConfig(creds BootstrapCredentials) *ssh.ClientConfig {
	auth := []ssh.AuthMethod{}
	if creds.AuthMethod == "password" {
		auth = append(auth, ssh.Password(creds.Password))
	} else {
		var signer ssh.Signer
		var err error
		if creds.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(creds.PrivateKey), []byte(creds.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(creds.PrivateKey))
		}
		if err == nil {
			auth = append(auth, ssh.PublicKeys(signer))
		}
	}
	return &ssh.ClientConfig{
		User:            creds.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}
}

func uploadSSHFile(client *ssh.Client, path string, content []byte) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, bytes.NewReader(content))
		_ = stdin.Close()
	}()
	return session.Run("cat > " + shellQuote(path))
}

func runSSHOutput(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out
	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func runPrivilegedSSH(client *ssh.Client, creds BootstrapCredentials, script string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := "printf %s " + shellQuote(encoded) + " | base64 -d | sh"
	var stdin string
	if creds.User != "root" {
		if creds.Password == "" {
			return errors.New("sudo password is required when bootstrap user is not root")
		}
		cmd = "sudo -S -p '' sh -c " + shellQuote(cmd)
		stdin = creds.Password + "\n"
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out
	if stdin != "" {
		w, err := session.StdinPipe()
		if err != nil {
			return err
		}
		go func() {
			_, _ = w.Write([]byte(stdin))
			_ = w.Close()
		}()
	}
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func shellUnitArg(v string) string {
	return strings.ReplaceAll(v, " ", "\\x20")
}

func (s *Server) requireClient(w http.ResponseWriter, r *http.Request) (APIKey, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "authentication_required", "missing bearer token")
		return APIKey{}, false
	}
	hash := hashSecret(strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.state.APIKeys {
		if k.Hash == hash && k.RevokedAt == nil {
			return k, true
		}
	}
	writeError(w, http.StatusUnauthorized, "authentication_required", "invalid token")
	return APIKey{}, false
}

func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request, expectedAgentID string) (Target, bool) {
	agentID := r.Header.Get("X-AccessGate-Agent-ID")
	ts := r.Header.Get("X-AccessGate-Agent-Timestamp")
	nonce := r.Header.Get("X-AccessGate-Agent-Nonce")
	sig := r.Header.Get("X-AccessGate-Agent-Signature")
	if agentID == "" || ts == "" || nonce == "" || sig == "" {
		writeError(w, http.StatusUnauthorized, "agent_auth_required", "missing agent authentication headers")
		return Target{}, false
	}
	if expectedAgentID != "" && agentID != expectedAgentID {
		writeError(w, http.StatusForbidden, "agent_id_mismatch", "agent identity does not match endpoint")
		return Target{}, false
	}
	when, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "agent_auth_invalid", "invalid agent timestamp")
		return Target{}, false
	}
	if d := time.Since(time.Unix(when, 0).UTC()); d > 2*time.Minute || d < -2*time.Minute {
		writeError(w, http.StatusUnauthorized, "agent_auth_stale", "agent timestamp outside allowed window")
		return Target{}, false
	}
	s.mu.Lock()
	var target Target
	found := false
	for _, t := range s.state.Targets {
		if t.ID == agentID {
			target = t
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found || target.AgentSecret == "" {
		writeError(w, http.StatusUnauthorized, "agent_unknown", "unknown or unprovisioned agent")
		return Target{}, false
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "agent_body_read_failed", err.Error())
			return Target{}, false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	bodySHA := sha256.Sum256(body)
	expected := agentSignature(target.AgentSecret, r.Method, r.URL.EscapedPath(), ts, nonce, hex.EncodeToString(bodySHA[:]))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		writeError(w, http.StatusUnauthorized, "agent_auth_invalid", "invalid agent signature")
		return Target{}, false
	}
	return target, true
}

func (s *Server) requireOps(w http.ResponseWriter, r *http.Request) (OpsSession, bool) {
	c, err := r.Cookie("ag_ops_session")
	if err != nil {
		s.opsInactive(w)
		return OpsSession{}, false
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, "state_load_failed", err.Error())
		return OpsSession{}, false
	}
	for _, sess := range s.state.OpsSessions {
		if sess.ID == c.Value && now.Before(sess.ExpiresAt) {
			return sess, true
		}
	}
	s.opsInactive(w)
	return OpsSession{}, false
}

func (s *Server) opsInactive(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "ops_ui_inactive", "message": "Operator Web UI is not active"}})
}

func (s *Server) loadLocked() error {
	b, err := os.ReadFile(s.stateFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &s.state)
}

func generateSSHKey(comment string) (string, string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", "", err
	}
	privateKey := string(pem.EncodeToMemory(block))
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), privateKey, ssh.FingerprintSHA256(sshPub), nil
}

func agentContractSchemas() map[string]any {
	return map[string]any{
		"createLease": map[string]any{
			"method":         "POST",
			"path":           "/v1/leases",
			"authentication": "Bearer client API key",
			"requiredFields": map[string]any{
				"target":        "string",
				"role":          "normal | serviceuser",
				"accessProfile": "normal | elevated",
				"timeframe":     map[string]string{"type": "duration | unlimited", "seconds": "number, required when type=duration"},
				"reason":        "string",
			},
			"derivedFields": map[string]string{"linuxUser": "AccessGate-owned user selected from accessProfile"},
			"keyDelivery":   map[string]string{"mode": "generated_once", "privateKey": "returned exactly once for active leases or after successful claim"},
			"example": map[string]any{
				"target": "server-a", "role": "normal", "accessProfile": "normal",
				"timeframe": map[string]any{"type": "duration", "seconds": 900},
				"reason":    "Investigate service health and logs",
			},
		},
		"activeLeaseResponse": map[string]any{
			"fields": map[string]string{
				"leaseId": "string", "version": "number", "generation": "number", "state": "active | pending_approval | approved | revoked | expired",
				"approvalRequired": "boolean", "target": "string", "host": "string", "role": "normal | serviceuser", "accessProfile": "normal | elevated",
				"linuxUser": "accessgate-normal | accessgate-elevated", "expiresAt": "RFC3339 timestamp or null", "keyDelivery": "generated_once",
				"keyFingerprint": "string", "privateKey": "OpenSSH private key, returned exactly once when key material is delivered",
			},
		},
		"targetResponse": map[string]any{
			"path": "/v1/targets",
			"fields": map[string]string{
				"target": "string", "displayName": "string", "host": "string", "sshPort": "number", "state": "active | pending_bootstrap | retiring | tombstone_sent",
				"agentStatus": "verified | unverified", "bootstrapStatus": "complete | queued | running | failed", "allowedRoles": "array", "allowedAccessProfiles": "array", "maxTtlSeconds": "number",
			},
		},
		"revokeLease": map[string]any{"method": "POST", "path": "/v1/leases/{leaseId}/revoke", "authentication": "Bearer client API key"},
		"claimCase":   map[string]any{"method": "POST", "path": "/v1/access-cases/{caseId}/claim", "authentication": "Bearer client API key"},
	}
}

func agentContractErrors() []map[string]any {
	return []map[string]any{
		{"code": "authentication_required", "httpStatus": 401, "meaning": "The endpoint requires a valid credential.", "recovery": "ask_user", "action": "Ask for a valid ACCESSGATE_API_TOKEN or refresh credentials."},
		{"code": "policy_denied", "httpStatus": 400, "meaning": "The requester is not allowed to create this lease or the request shape is invalid.", "recovery": "ask_user", "action": "Check target, role, accessProfile, timeframe.seconds, and policy. Ask the user if policy access is missing."},
		{"code": "approval_required", "httpStatus": 202, "meaning": "The request created an approval case.", "recovery": "wait_for_approval", "action": "Store caseId and call the claim endpoint after human approval."},
		{"code": "case_pending", "httpStatus": 202, "meaning": "The approval case has not been approved yet.", "recovery": "wait_for_approval", "action": "Wait and retry claim later."},
		{"code": "case_not_claimable", "httpStatus": 409, "meaning": "The case is rejected, revoked, expired, already claimed, or belongs to another requester.", "recovery": "ask_user", "action": "Stop and ask for a new approval or lease."},
		{"code": "ttl_too_long", "httpStatus": 400, "meaning": "Requested normal access exceeds target max TTL or 3600 seconds.", "recovery": "reduce_ttl", "action": "Retry with timeframe.seconds at or below maxTtlSeconds and 3600."},
		{"code": "rate_limited", "httpStatus": 429, "meaning": "Requester exceeded configured rate or concurrent lease quota.", "recovery": "retry", "action": "Wait retryAfterSeconds when provided, otherwise back off before retrying."},
		{"code": "not_found", "httpStatus": 404, "meaning": "Lease, case, or endpoint was not found.", "recovery": "ask_user", "action": "Verify IDs and endpoint paths; do not guess target names."},
	}
}

func leaseResponse(l Lease) map[string]any {
	return map[string]any{"leaseId": l.ID, "version": l.Version, "generation": l.Generation, "caseId": l.CaseID, "state": l.State, "approvalRequired": l.State == "pending_approval", "target": l.Target, "host": l.Host, "role": l.Role, "accessProfile": l.AccessProfile, "linuxUser": l.LinuxUser, "expiresAt": l.ExpiresAt, "keyDelivery": l.KeyDelivery, "keyFingerprint": l.KeyFingerprint}
}

func normalizeRestrictions(r Restrictions) Restrictions {
	return Restrictions{PTY: r.PTY, AgentForwarding: r.AgentForwarding, X11Forwarding: r.X11Forwarding, PortForwarding: r.PortForwarding}
}

func normalizeTarget(id, displayName, host string, sshPort int, roles, profiles []string, maxTTL int) (Target, error) {
	id = strings.TrimSpace(id)
	displayName = strings.TrimSpace(displayName)
	host = strings.TrimSpace(host)
	if id == "" {
		id = strings.ToLower(strings.ReplaceAll(displayName, " ", "-"))
	}
	if displayName == "" {
		displayName = id
	}
	if id == "" || host == "" {
		return Target{}, errors.New("target and host are required")
	}
	if strings.ContainsAny(id, "/\\ \t\r\n") {
		return Target{}, errors.New("target may not contain whitespace or slashes")
	}
	if len(roles) == 0 {
		roles = []string{"normal"}
	}
	if len(profiles) == 0 {
		profiles = defaultAccessProfiles()
	}
	for _, profile := range profiles {
		if _, ok := accessProfileLinuxUsers[profile]; !ok {
			return Target{}, fmt.Errorf("unsupported access profile %q", profile)
		}
	}
	if maxTTL <= 0 || maxTTL > 3600 {
		maxTTL = 3600
	}
	if sshPort <= 0 {
		sshPort = 22
	}
	return Target{ID: id, DisplayName: displayName, Host: host, SSHPort: sshPort, AllowedRoles: uniqueStrings(roles), AllowedProfiles: uniqueStrings(profiles), MaxTTLSeconds: maxTTL}, nil
}

func (b BootstrapCredentials) validate() error {
	if strings.TrimSpace(b.User) == "" {
		return errors.New("bootstrap user is required")
	}
	switch b.AuthMethod {
	case "password":
		if b.Password == "" {
			return errors.New("bootstrap password is required")
		}
	case "ssh_key":
		if strings.TrimSpace(b.PrivateKey) == "" {
			return errors.New("bootstrap private key is required")
		}
	default:
		return errors.New("bootstrap auth method must be password or ssh_key")
	}
	return nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func uniqueStrings(xs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func (s *Server) findTarget(id string) (Target, bool) {
	for _, t := range s.state.Targets {
		if t.ID == id || t.DisplayName == id {
			return t, true
		}
	}
	return Target{}, false
}

func (s *Server) hasAPIKeyHash(hash string) bool {
	for _, k := range s.state.APIKeys {
		if k.Hash == hash {
			return true
		}
	}
	return false
}

func (s *Server) auditLocked(t, actor, msg string) {
	s.state.Events = append(s.state.Events, AuditEvent{ID: "evt_" + token(12), Type: t, Actor: actor, Message: msg, Timestamp: time.Now().UTC()})
}

func hashSecret(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func defaultAccessProfiles() []string {
	return []string{accessProfileNormal, accessProfileElevated}
}

func accessProfileForLinuxUser(linuxUser string) string {
	for profile, user := range accessProfileLinuxUsers {
		if user == linuxUser {
			return profile
		}
	}
	return ""
}

func resolveAccessProfile(profile, legacyLinuxUser string) (string, string, error) {
	profile = strings.TrimSpace(profile)
	legacyLinuxUser = strings.TrimSpace(legacyLinuxUser)
	if profile == "" && legacyLinuxUser != "" {
		profile = accessProfileForLinuxUser(legacyLinuxUser)
	}
	if profile == "" {
		return "", "", errors.New("accessProfile is required")
	}
	linuxUser, ok := accessProfileLinuxUsers[profile]
	if !ok {
		return "", "", fmt.Errorf("unsupported accessProfile %q", profile)
	}
	if legacyLinuxUser != "" && legacyLinuxUser != linuxUser {
		return "", "", errors.New("linuxUser is managed by AccessGate; use accessProfile instead")
	}
	return profile, linuxUser, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeEncryptedJSON(w http.ResponseWriter, status int, secret string, v any) {
	plain, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "json_encode_failed", err.Error())
		return
	}
	env, err := encryptAgentEnvelope(secret, plain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_encrypt_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-AccessGate-Encrypted", "aesgcm-v1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func writeEncryptedBytes(w http.ResponseWriter, status int, secret string, plain []byte) {
	env, err := encryptAgentEnvelope(secret, plain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_encrypt_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-AccessGate-Encrypted", "aesgcm-v1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

var opsTemplate = template.Must(template.New("ops").Funcs(template.FuncMap{"humanTime": func(t time.Time) string {
	return t.Local().Format("02 Jan 2006, 15:04 MST")
}, "humanTimePtr": func(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("02 Jan 2006, 15:04 MST")
}, "timeTitle": func(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}, "timeTitlePtr": func(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}, "ttl": func(t *time.Time) string {
	if t == nil {
		return "unlimited"
	}
	seconds := int64(time.Until(*t).Seconds())
	if seconds <= 0 {
		return "expired"
	}
	return strconv.FormatInt(seconds, 10) + "s"
}}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if and (eq .Page "leases") .AutoRefresh}}<meta http-equiv="refresh" content="5;url=/ops/leases?refresh=1">{{end}}
<title>AccessGate Ops</title>
<style>
body{margin:0;background:#101214;color:#e8ecef;font:14px system-ui,Segoe UI,sans-serif}
header{padding:18px 24px;border-bottom:1px solid #2b3035;display:flex;justify-content:space-between;gap:16px;align-items:center}
nav{display:flex;gap:8px;flex-wrap:wrap}
nav a,.link{color:#dce7f2;text-decoration:none;background:#1b2229;border:1px solid #2b3035;border-radius:6px;padding:7px 10px}
main{padding:24px;display:grid;gap:20px}
table{width:100%;border-collapse:collapse;background:#161a1e}
th,td{padding:10px;border-bottom:1px solid #2b3035;text-align:left}
th{color:#9fb0bf;font-weight:600}
.table-wrap{overflow:auto;border:1px solid #2b3035;background:#161a1e}
.table-wrap table{background:transparent}
.pill{padding:3px 8px;border-radius:999px;background:#26313b}
.pending,.pending_approval{color:#ffd166}.active,.verified,.complete{color:#74d680}.revoked,.failed,.bootstrap_failed{color:#ff6b6b}.unverified{color:#a8b3bd}
button{background:#2f81f7;color:white;border:0;padding:7px 10px;border-radius:6px;cursor:pointer}
button.ghost{background:#1b2229;color:#dce7f2;border:1px solid #2b3035}
button[disabled]{opacity:.45;cursor:not-allowed}
button.danger,.link.danger{background:#8b1d2c;border-color:#b83245;color:#fff}
button.warn,.link.warn{background:#7a4f00;border-color:#b7791f;color:#fff}
section{display:grid;gap:10px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #2b3035}
.tab{border-radius:6px 6px 0 0;border:1px solid #2b3035;border-bottom:0;background:#1b2229;color:#dce7f2;padding:9px 12px}
.tab.active{background:#2f81f7;color:#fff;border-color:#2f81f7}
.audit-panel{display:none;gap:12px}
.audit-panel.active{display:grid}
.audit-tools{display:grid;grid-template-columns:minmax(220px,1fr) 180px 140px auto;gap:10px;align-items:end;background:#161a1e;border:1px solid #2b3035;padding:12px}
.audit-pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap}
.audit-empty{display:none;color:#9fb0bf;background:#161a1e;border:1px solid #2b3035;padding:14px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px}
.stat{background:#161a1e;border:1px solid #2b3035;padding:14px;border-radius:6px}
.stat strong{display:block;font-size:26px;margin-top:6px}
form.grid{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:10px;align-items:end;background:#161a1e;padding:14px;border:1px solid #2b3035}
label{display:grid;gap:6px;color:#9fb0bf;font-size:12px}
input,select,textarea{background:#0f1215;color:#e8ecef;border:1px solid #2b3035;border-radius:6px;padding:8px;min-width:0}
textarea{height:96px;resize:vertical}
code,pre{background:#0f1215;border:1px solid #2b3035;border-radius:6px;color:#dce7f2}
code{padding:2px 5px}
pre{padding:12px;overflow:auto;white-space:pre-wrap}
.muted{color:#9fb0bf}
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.62);padding:24px;overflow:auto}
.modal:target{display:grid;place-items:start center}
.modal-panel{background:#161a1e;border:1px solid #2b3035;border-radius:8px;max-width:1040px;width:min(1040px,100%);padding:18px;display:grid;gap:12px}
.modal-head{display:flex;justify-content:space-between;gap:12px;align-items:center}
@media(max-width:900px){form.grid,.cards,.audit-tools{grid-template-columns:1fr}table{font-size:12px}header{align-items:flex-start;flex-direction:column}.audit-pager{justify-content:flex-start}}
</style>
</head>
<body>
<header>
<div><strong>AccessGate Ops</strong><br><span>{{.Session.Operator}} · <time title="{{timeTitle .Session.ExpiresAt}}">{{humanTime .Session.ExpiresAt}}</time></span></div>
<nav>
<a href="/ops">Overview</a>
<a href="/ops/leases">Leases</a>
<a href="/ops/targets">Servers</a>
<a href="/ops/api-keys">API Keys</a>
<a href="/ops/audit">Audit</a>
<a href="/ops/help">Help</a>
</nav>
</header>
<main>

{{if eq .Page "dashboard"}}
<section>
<h2>Overview</h2>
<div class="cards">
<div class="stat">Leases<strong data-count="leases">{{len .Leases}}</strong></div>
<div class="stat">Servers<strong data-count="targets">{{len .Targets}}</strong></div>
<div class="stat">API Keys<strong data-count="apiKeys">{{len .APIKeys}}</strong></div>
<div class="stat">Session<strong>{{.Session.Operator}}</strong></div>
</div>
</section>
{{end}}

{{if eq .Page "leases"}}
<section>
<h2>Leases</h2>
<p><a class="link" href="/ops/leases">Refresh</a> <span class="muted">Live status updates are enabled.</span></p>
<table><thead><tr><th>Lease</th><th>State</th><th>Target</th><th>Profile</th><th>User</th><th>Role</th><th>TTL</th><th>Reason</th><th></th></tr></thead><tbody>
{{range .Leases}}
<tr data-lease-id="{{.ID}}"><td>{{.ID}}</td><td data-lease-state class="{{.State}}">{{.State}}</td><td>{{.Target}}</td><td>{{.AccessProfile}}</td><td>{{.LinuxUser}}</td><td>{{.Role}}</td><td data-lease-ttl>{{ttl .ExpiresAt}}</td><td>{{.Reason}}</td><td>{{if eq .State "pending_approval"}}<form method="post" action="/v1/leases/{{.ID}}/approve"><button>Approve</button></form>{{end}}</td></tr>
{{end}}
</tbody></table>
</section>
{{end}}

{{if eq .Page "targets"}}
<section>
<h2>Servers</h2>
<p><a class="link" href="#add-server">Add Server</a></p>
<table><thead><tr><th>Target</th><th>Host</th><th>State</th><th>Agent</th><th>Profiles</th><th>Roles</th><th></th></tr></thead><tbody>
{{range .Targets}}<tr data-target-id="{{.ID}}"><td>{{.DisplayName}}</td><td>{{.Host}}:{{.SSHPort}}</td><td data-target-state class="{{.State}}">{{.State}} {{if .BootstrapMessage}}<br>{{.BootstrapMessage}}{{end}}</td><td data-agent-status class="{{.AgentStatus}}">{{.AgentStatus}}</td><td>{{range .AllowedProfiles}}<span class="pill">{{.}}</span> {{end}}</td><td>{{range .AllowedRoles}}<span class="pill">{{.}}</span> {{end}}</td><td><a class="link warn" href="#retire-{{.ID}}">Retire</a> <a class="link danger" href="#kill-{{.ID}}">Kill</a></td></tr>{{end}}
</tbody></table>
</section>
{{range .Targets}}
<div id="retire-{{.ID}}" class="modal">
<div class="modal-panel">
<div class="modal-head"><h2>Retire {{.DisplayName}}</h2><a class="link" href="/ops/targets">Close</a></div>
<p class="muted">Retire is the normal removal path. AccessGate sends a trusted retire command, the AG-Agent removes AccessGate-managed keys and local certificate material, then uninstalls itself. Certificate and secret are revoked after completion or timeout.</p>
<form method="post" action="/v1/admin/targets/{{.ID}}/retire">
<button class="warn" type="submit">Confirm Retire</button>
</form>
</div>
</div>
<div id="kill-{{.ID}}" class="modal">
<div class="modal-panel">
<div class="modal-head"><h2>Kill {{.DisplayName}}</h2><a class="link" href="/ops/targets">Close</a></div>
<p class="muted">Kill is destructive. AccessGate sends one final trusted tombstone command, waits only a short grace period, then revokes the AG-Agent certificate and secret even if no confirmation arrives.</p>
<form method="post" action="/v1/admin/targets/{{.ID}}/kill">
<button class="danger" type="submit">Confirm Kill</button>
</form>
</div>
</div>
{{end}}
<div id="add-server" class="modal">
<div class="modal-panel">
<div class="modal-head"><h2>Add Server</h2><a class="link" href="/ops/targets">Close</a></div>
<form class="grid" method="post" action="/v1/admin/targets">
<label>Target<input name="target" placeholder="server-x" required></label>
<label>Name<input name="displayName" placeholder="Server X"></label>
<label>Host/IP<input name="host" placeholder="10.0.0.50" required></label>
<label>SSH Port<input name="sshPort" type="number" min="1" max="65535" value="22"></label>
<label>Bootstrap User<input name="bootstrapUser" placeholder="root" required></label>
<label>Auth<select name="bootstrapAuthMethod"><option value="password">Password</option><option value="ssh_key">SSH Key</option></select></label>
<label>Password<input name="bootstrapPassword" type="password" autocomplete="off"></label>
<label>Private Key<textarea name="bootstrapPrivateKey" autocomplete="off"></textarea></label>
<label>Passphrase<input name="bootstrapPrivateKeyPassphrase" type="password" autocomplete="off"></label>
<label>Profiles<input name="allowedAccessProfiles" value="normal,elevated"></label>
<label>Roles<input name="allowedRoles" value="normal,serviceuser"></label>
<label>Max Lease TTL<input name="maxTtlSeconds" type="number" min="60" max="3600" value="3600"></label>
<button type="submit">Add</button>
</form>
</div>
</div>
{{end}}

{{if eq .Page "api-keys"}}
<section>
<h2>API Keys</h2>
<p><a class="link" href="#add-api-key">Add API Key</a></p>
<table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Requester</th><th>Created</th><th>State</th><th></th></tr></thead><tbody>
{{range .APIKeys}}<tr><td>{{.ID}}</td><td>{{.DisplayName}}</td><td>{{.RequesterType}}</td><td>{{.RequesterID}}</td><td><time title="{{timeTitle .CreatedAt}}">{{humanTime .CreatedAt}}</time></td><td>active</td><td><form method="post" action="/v1/admin/api-keys/{{.ID}}/revoke"><button>Revoke</button></form></td></tr>{{end}}
</tbody></table>
</section>
<div id="add-api-key" class="modal">
<div class="modal-panel">
<div class="modal-head"><h2>Add API Key</h2><a class="link" href="/ops/api-keys">Close</a></div>
<form class="grid" method="post" action="/v1/admin/api-keys">
<label>Name<input name="displayName" placeholder="codex-agent-main" required></label>
<label>Type<select name="requesterType"><option value="ai_agent">AI Agent</option><option value="service">Service</option><option value="user">User</option></select></label>
<label>Owner<input name="owner" placeholder="operator"></label>
<label>Policy Groups<input name="policyGroups" placeholder="ai-agent-standard"></label>
<button type="submit">Create</button>
</form>
</div>
</div>
{{end}}

{{if eq .Page "audit"}}
<section data-audit>
<h2>Audit / History</h2>
<div class="tabs" role="tablist">
<button class="tab active" type="button" data-audit-tab="leases">Lease History <span class="muted">({{len .LeaseHistory}})</span></button>
<button class="tab" type="button" data-audit-tab="api-keys">API Keys <span class="muted">({{len .APIKeyHistory}})</span></button>
<button class="tab" type="button" data-audit-tab="events">Events <span class="muted">({{len .Events}})</span></button>
</div>

<div class="audit-panel active" data-audit-panel="leases">
<div class="audit-tools">
<label>Search<input data-audit-search placeholder="Lease, target, user, reason"></label>
<label>State<select data-audit-filter><option value="">All states</option></select></label>
<label>Rows<select data-audit-size><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
<div class="audit-pager"><button class="ghost" type="button" data-audit-prev>Prev</button><span class="muted" data-audit-page></span><button class="ghost" type="button" data-audit-next>Next</button></div>
</div>
<div class="table-wrap"><table><thead><tr><th>Lease</th><th>State</th><th>Target</th><th>Profile</th><th>User</th><th>Role</th><th>Created</th><th>Expired</th><th>Reason</th></tr></thead><tbody>
{{range .LeaseHistory}}<tr data-filter-value="{{.State}}"><td>{{.ID}}</td><td class="{{.State}}">{{.State}}</td><td>{{.Target}}</td><td>{{.AccessProfile}}</td><td>{{.LinuxUser}}</td><td>{{.Role}}</td><td><time title="{{timeTitle .CreatedAt}}">{{humanTime .CreatedAt}}</time></td><td><time title="{{timeTitlePtr .ExpiresAt}}">{{humanTimePtr .ExpiresAt}}</time></td><td>{{.Reason}}</td></tr>{{end}}
</tbody></table></div>
<div class="audit-empty">No lease history matches the current filters.</div>
</div>

<div class="audit-panel" data-audit-panel="api-keys">
<div class="audit-tools">
<label>Search<input data-audit-search placeholder="Key, name, type, requester"></label>
<label>Type<select data-audit-filter><option value="">All types</option></select></label>
<label>Rows<select data-audit-size><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
<div class="audit-pager"><button class="ghost" type="button" data-audit-prev>Prev</button><span class="muted" data-audit-page></span><button class="ghost" type="button" data-audit-next>Next</button></div>
</div>
<div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Requester</th><th>Created</th><th>Revoked</th></tr></thead><tbody>
{{range .APIKeyHistory}}<tr data-filter-value="{{.RequesterType}}"><td>{{.ID}}</td><td>{{.DisplayName}}</td><td>{{.RequesterType}}</td><td>{{.RequesterID}}</td><td><time title="{{timeTitle .CreatedAt}}">{{humanTime .CreatedAt}}</time></td><td><time title="{{timeTitlePtr .RevokedAt}}">{{humanTimePtr .RevokedAt}}</time></td></tr>{{end}}
</tbody></table></div>
<div class="audit-empty">No API key history matches the current filters.</div>
</div>

<div class="audit-panel" data-audit-panel="events">
<div class="audit-tools">
<label>Search<input data-audit-search placeholder="Type, actor, message"></label>
<label>Type<select data-audit-filter><option value="">All event types</option></select></label>
<label>Rows<select data-audit-size><option value="20">20</option><option value="50">50</option><option value="100">100</option></select></label>
<div class="audit-pager"><button class="ghost" type="button" data-audit-prev>Prev</button><span class="muted" data-audit-page></span><button class="ghost" type="button" data-audit-next>Next</button></div>
</div>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Actor</th><th>Message</th></tr></thead><tbody>
{{range .Events}}<tr data-filter-value="{{.Type}}"><td><time title="{{timeTitle .Timestamp}}">{{humanTime .Timestamp}}</time></td><td>{{.Type}}</td><td>{{.Actor}}</td><td>{{.Message}}</td></tr>{{end}}
</tbody></table></div>
<div class="audit-empty">No events match the current filters.</div>
</div>
</section>
{{end}}

{{if eq .Page "help"}}
<section>
<h2>API Help</h2>
<p class="muted">Public discovery starts with the informer. Authenticated endpoints use requester API keys unless marked as Ops or internal agent endpoints.</p>
</section>
<section>
<h3>Public Informer</h3>
<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>
<tr><td>GET</td><td><code>/v1/informer</code></td><td>Public entrypoint for agents and automation to discover AccessGate behavior.</td></tr>
<tr><td>GET</td><td><code>/v1/informer/agent-contract</code></td><td>Complete machine-readable contract for AI agents, including schemas, examples, retry rules, cleanup rules, and error recovery.</td></tr>
<tr><td>GET</td><td><code>/v1/informer/process</code></td><td>High-level request and approval process information.</td></tr>
<tr><td>GET</td><td><code>/v1/informer/schema</code></td><td>Request schema hints for lease creation and claim flows.</td></tr>
<tr><td>GET</td><td><code>/v1/informer/errors</code></td><td>Known error codes and meanings.</td></tr>
</tbody></table>
</section>
<section>
<h3>Requester API</h3>
<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>
<tr><td>GET</td><td><code>/v1/targets</code></td><td>List available target servers for the authenticated requester.</td></tr>
<tr><td>POST</td><td><code>/v1/leases</code></td><td>Create a normal lease or start a pending approval case for unlimited serviceuser access.</td></tr>
<tr><td>GET</td><td><code>/v1/leases/{leaseId}</code></td><td>Read one active lease.</td></tr>
<tr><td>POST</td><td><code>/v1/leases/{leaseId}/revoke</code></td><td>Revoke an active lease and trigger rapid AG-Agent key removal.</td></tr>
<tr><td>POST</td><td><code>/v1/access-cases/{caseId}/claim</code></td><td>Claim an approved pending case and receive the generated private key once.</td></tr>
</tbody></table>
<pre>{
  "target": "server-b",
  "role": "normal",
  "accessProfile": "normal",
  "reason": "maintenance task",
  "timeframe": {"type": "duration", "seconds": 1800}
}</pre>
</section>
<section>
<h3>Ops Web UI</h3>
<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>
<tr><td>GET</td><td><code>/ops</code></td><td>Overview, only active while an Ops session exists.</td></tr>
<tr><td>GET</td><td><code>/ops/leases</code></td><td>Active and pending leases only.</td></tr>
<tr><td>GET</td><td><code>/ops/targets</code></td><td>Server inventory and Add Server modal.</td></tr>
<tr><td>GET</td><td><code>/ops/api-keys</code></td><td>Active requester API keys.</td></tr>
<tr><td>GET</td><td><code>/ops/audit</code></td><td>Expired/revoked lease history, revoked API key history, and events.</td></tr>
<tr><td>GET</td><td><code>/ops/help</code></td><td>This endpoint overview.</td></tr>
</tbody></table>
</section>
<section>
<h3>Ops Admin Actions</h3>
<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>
<tr><td>POST</td><td><code>/v1/leases/{leaseId}/approve</code></td><td>Approve a pending unlimited serviceuser lease.</td></tr>
<tr><td>POST</td><td><code>/v1/admin/api-keys</code></td><td>Create a requester API key and show the secret once.</td></tr>
<tr><td>POST</td><td><code>/v1/admin/api-keys/{keyId}/revoke</code></td><td>Revoke an active requester API key.</td></tr>
<tr><td>POST</td><td><code>/v1/admin/targets</code></td><td>Add or update a target and bootstrap the AG-Agent.</td></tr>
<tr><td>POST</td><td><code>/v1/admin/targets/{targetId}/delete</code></td><td>Delete a target when no active lease references it.</td></tr>
</tbody></table>
</section>
<section>
<h3>AG-Agent Internal</h3>
<table><thead><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr></thead><tbody>
<tr><td>GET</td><td><code>/v1/agents/{agentId}/desired-state</code></td><td>Agent pulls the complete desired lease state for its target.</td></tr>
<tr><td>POST</td><td><code>/v1/agent/leases/{leaseId}/revoke-notify</code></td><td>AG-Server rapid revoke push to remove a key and terminate affected SSH sessions.</td></tr>
<tr><td>GET</td><td><code>/v1/agent-binaries/{arch}/meta</code></td><td>Agent auto-updater reads published binary metadata and SHA-256.</td></tr>
<tr><td>GET</td><td><code>/v1/agent-binaries/{arch}</code></td><td>Agent auto-updater downloads the matching binary after checksum comparison.</td></tr>
</tbody></table>
<p class="muted">AG-Agent endpoints use per-agent shared secrets, HMAC-signed requests, timestamp validation, and AES-GCM encrypted envelopes for desired state, update metadata, and agent binaries. Requester API keys are not the agent trust channel. mTLS can still be added later as an additional transport identity layer.</p>
</section>
{{end}}

</main>
<script>
(() => {
  const cls = ["pending","pending_approval","active","verified","complete","revoked","failed","bootstrap_failed","unverified","retiring","tombstone_sent"];
  const setText = (el, value) => { if (el && el.textContent !== String(value)) el.textContent = value; };
  const setState = (el, value, extra) => {
    if (!el) return;
    cls.forEach(c => el.classList.remove(c));
    if (value) el.classList.add(value);
    el.innerHTML = extra ? String(value) + "<br>" + String(extra) : value;
  };
  function setupAudit() {
    const root = document.querySelector("[data-audit]");
    if (!root) return;
    const tabs = Array.from(root.querySelectorAll("[data-audit-tab]"));
    const panels = Array.from(root.querySelectorAll("[data-audit-panel]"));
    const states = new Map();
    function panelRows(panel) {
      return Array.from(panel.querySelectorAll("tbody tr"));
    }
    function state(panel) {
      const name = panel.dataset.auditPanel;
      if (!states.has(name)) states.set(name, {page: 1});
      return states.get(name);
    }
    function fillFilter(panel) {
      const select = panel.querySelector("[data-audit-filter]");
      if (!select) return;
      const values = Array.from(new Set(panelRows(panel).map(row => row.dataset.filterValue || "").filter(Boolean))).sort();
      for (const value of values) {
        const option = document.createElement("option");
        option.value = value.toLowerCase();
        option.textContent = value;
        select.appendChild(option);
      }
    }
    function render(panel) {
      const s = state(panel);
      const rows = panelRows(panel);
      const query = (panel.querySelector("[data-audit-search]")?.value || "").trim().toLowerCase();
      const filter = (panel.querySelector("[data-audit-filter]")?.value || "").trim().toLowerCase();
      const size = Number(panel.querySelector("[data-audit-size]")?.value || "20");
      const matched = rows.filter(row => {
        const textOK = !query || row.textContent.toLowerCase().includes(query);
        const filterOK = !filter || (row.dataset.filterValue || "").toLowerCase() === filter;
        return textOK && filterOK;
      });
      const pages = Math.max(1, Math.ceil(matched.length / size));
      s.page = Math.min(Math.max(1, s.page), pages);
      const start = (s.page - 1) * size;
      const visible = new Set(matched.slice(start, start + size));
      for (const row of rows) row.style.display = visible.has(row) ? "" : "none";
      const page = panel.querySelector("[data-audit-page]");
      const prev = panel.querySelector("[data-audit-prev]");
      const next = panel.querySelector("[data-audit-next]");
      const empty = panel.querySelector(".audit-empty");
      if (page) page.textContent = matched.length === 0 ? "0 of 0" : "Page " + s.page + " of " + pages + " · " + matched.length + " rows";
      if (prev) prev.disabled = s.page <= 1;
      if (next) next.disabled = s.page >= pages;
      if (empty) empty.style.display = matched.length === 0 ? "block" : "none";
    }
    for (const panel of panels) {
      fillFilter(panel);
      panel.querySelector("[data-audit-search]")?.addEventListener("input", () => { state(panel).page = 1; render(panel); });
      panel.querySelector("[data-audit-filter]")?.addEventListener("change", () => { state(panel).page = 1; render(panel); });
      panel.querySelector("[data-audit-size]")?.addEventListener("change", () => { state(panel).page = 1; render(panel); });
      panel.querySelector("[data-audit-prev]")?.addEventListener("click", () => { state(panel).page--; render(panel); });
      panel.querySelector("[data-audit-next]")?.addEventListener("click", () => { state(panel).page++; render(panel); });
      render(panel);
    }
    for (const tab of tabs) {
      tab.addEventListener("click", () => {
        const name = tab.dataset.auditTab;
        for (const t of tabs) t.classList.toggle("active", t === tab);
        for (const panel of panels) {
          const active = panel.dataset.auditPanel === name;
          panel.classList.toggle("active", active);
          if (active) render(panel);
        }
      });
    }
  }
  async function refreshStatus() {
    try {
      const res = await fetch("/ops/status", {cache: "no-store"});
      if (!res.ok) return;
      const data = await res.json();
      if (data.counts) {
        setText(document.querySelector("[data-count='leases']"), data.counts.leases);
        setText(document.querySelector("[data-count='targets']"), data.counts.targets);
        setText(document.querySelector("[data-count='apiKeys']"), data.counts.apiKeys);
      }
      for (const target of data.targets || []) {
        const row = document.querySelector("[data-target-id=\"" + CSS.escape(target.id) + "\"]");
        if (!row) continue;
        setState(row.querySelector("[data-target-state]"), target.state, target.bootstrapMessage || "");
        setState(row.querySelector("[data-agent-status]"), target.agentStatus, "");
      }
      for (const lease of data.leases || []) {
        const row = document.querySelector("[data-lease-id=\"" + CSS.escape(lease.id) + "\"]");
        if (!row) continue;
        setState(row.querySelector("[data-lease-state]"), lease.state, "");
        setText(row.querySelector("[data-lease-ttl]"), lease.ttl);
      }
    } catch (_) {}
  }
  setupAudit();
  setInterval(refreshStatus, 2000);
  refreshStatus();
})();
</script>
</body></html>`))
