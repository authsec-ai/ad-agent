package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/yaml.v2"
)

// Configuration structure
type Config struct {
	UserFlowAPI     APIConfig  `yaml:"userflow_api"`
	ActiveDirectory ADConfig   `yaml:"active_directory"`
	SyncSettings    SyncConfig `yaml:"sync_settings"`
}

type APIConfig struct {
	BaseURL    string `yaml:"base_url"`
	TenantID   string `yaml:"tenant_id"`
	ClientID   string `yaml:"client_id"`
	ProjectID  string `yaml:"project_id"`
	SkipVerify bool   `yaml:"skip_verify"`
}

type ADConfig struct {
	Server     string `yaml:"server"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	BaseDN     string `yaml:"base_dn"`
	Filter     string `yaml:"filter"`
	UseSSL     bool   `yaml:"use_ssl"`
	SkipVerify bool   `yaml:"skip_verify"`
}

type SyncConfig struct {
	IntervalMinutes int  `yaml:"interval_minutes"`
	DryRun          bool `yaml:"dry_run"`
	SyncGroups      bool `yaml:"sync_groups"`
	MaxUsers        int  `yaml:"max_users"`
}

// ADUser represents a user from Active Directory
type ADUser struct {
	ObjectGUID        string            `json:"object_guid"`
	UserPrincipalName string            `json:"user_principal_name"`
	DisplayName       string            `json:"display_name"`
	Email             string            `json:"email"`
	Username          string            `json:"username"`
	Department        string            `json:"department"`
	Title             string            `json:"title"`
	Groups            []string          `json:"groups"`
	Attributes        map[string]string `json:"attributes"`
	IsActive          bool              `json:"is_active"`
}

// API request structures
type SyncRequest struct {
	TenantID  string    `json:"tenant_id"`
	ClientID  string    `json:"client_id"`
	ProjectID string    `json:"project_id"`
	Users     []APIUser `json:"users"`
	DryRun    bool      `json:"dry_run"`
}

type APIUser struct {
	ExternalID   string                 `json:"external_id"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	Username     string                 `json:"username"`
	Provider     string                 `json:"provider"`
	ProviderID   string                 `json:"provider_id"`
	ProviderData map[string]interface{} `json:"provider_data"`
	IsActive     bool                   `json:"is_active"`
	IsSyncedUser bool                   `json:"is_synced_user"`
	SyncSource   string                 `json:"sync_source"`
}

// Windows service structure
type ADSyncService struct {
	config *Config
	logger *log.Logger
}

func main() {
	// Check if running as service or console
	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("Failed to determine if running interactively: %v", err)
	}

	if !isIntSess {
		// Running as Windows service
		runService()
	} else {
		// Running as console application for testing
		runConsole()
	}
}

func runService() {
	elog, err := eventlog.Open("ADSyncAgent")
	if err != nil {
		log.Fatalf("Failed to open event log: %v", err)
	}
	defer elog.Close()

	elog.Info(1, "Starting AD Sync Agent service")

	err = svc.Run("ADSyncAgent", &ADSyncService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
	}
}

func runConsole() {
	fmt.Println("AD Sync Agent - Console Mode")
	fmt.Println("Loading configuration...")

	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	agent := &ADSyncService{
		config: config,
		logger: log.New(os.Stdout, "[ADSync] ", log.LstdFlags),
	}

	agent.logger.Println("Starting sync process...")
	if err := agent.performSync(); err != nil {
		agent.logger.Printf("Sync failed: %v", err)
		os.Exit(1)
	}

	agent.logger.Println("Sync completed successfully")
}

// Windows service implementation
func (s *ADSyncService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// Load configuration
	config, err := loadConfig("config.yaml")
	if err != nil {
		return false, 1
	}
	s.config = config

	// Setup logger for service
	elog, _ := eventlog.Open("ADSyncAgent")
	defer elog.Close()
	s.logger = log.New(os.Stdout, "[ADSync] ", log.LstdFlags)

	changes <- svc.Status{State: svc.StartPending}

	// Start the sync timer
	syncTicker := time.NewTicker(time.Duration(s.config.SyncSettings.IntervalMinutes) * time.Minute)
	defer syncTicker.Stop()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	s.logger.Printf("AD Sync Agent started, syncing every %d minutes", s.config.SyncSettings.IntervalMinutes)
	elog.Info(1, fmt.Sprintf("AD Sync Agent started, syncing every %d minutes", s.config.SyncSettings.IntervalMinutes))

	// Perform initial sync
	go func() {
		if err := s.performSync(); err != nil {
			s.logger.Printf("Initial sync failed: %v", err)
			elog.Error(1, fmt.Sprintf("Initial sync failed: %v", err))
		}
	}()

loop:
	for {
		select {
		case <-syncTicker.C:
			// Perform periodic sync
			go func() {
				if err := s.performSync(); err != nil {
					s.logger.Printf("Scheduled sync failed: %v", err)
					elog.Error(1, fmt.Sprintf("Scheduled sync failed: %v", err))
				}
			}()

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.logger.Println("Stopping AD Sync Agent...")
				elog.Info(1, "Stopping AD Sync Agent")
				break loop
			default:
				s.logger.Printf("Unexpected service command: %v", c.Cmd)
				elog.Error(1, fmt.Sprintf("Unexpected service command: %v", c.Cmd))
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	return false, 0
}

func (s *ADSyncService) performSync() error {
	s.logger.Println("Starting AD sync process...")

	// Connect to AD and fetch users
	adUsers, err := s.fetchADUsers()
	if err != nil {
		return fmt.Errorf("failed to fetch AD users: %w", err)
	}

	s.logger.Printf("Found %d users in Active Directory", len(adUsers))

	if s.config.SyncSettings.DryRun {
		s.logger.Println("Dry run mode - not syncing to UserFlow")
		for i, user := range adUsers {
			if i >= 5 { // Limit preview
				break
			}
			s.logger.Printf("Preview user: %s (%s)", user.Email, user.DisplayName)
		}
		return nil
	}

	// Convert AD users to API format
	apiUsers := s.convertToAPIUsers(adUsers)

	// Send to UserFlow API
	if err := s.syncToUserFlow(apiUsers); err != nil {
		return fmt.Errorf("failed to sync to UserFlow: %w", err)
	}

	s.logger.Printf("Successfully synced %d users to UserFlow", len(apiUsers))
	return nil
}

func (s *ADSyncService) fetchADUsers() ([]ADUser, error) {
	// Connect to AD
	var conn *ldap.Conn
	var err error

	if s.config.ActiveDirectory.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: s.config.ActiveDirectory.SkipVerify,
		}
		conn, err = ldap.DialTLS("tcp", s.config.ActiveDirectory.Server, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", s.config.ActiveDirectory.Server)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to AD: %w", err)
	}
	defer conn.Close()

	// Bind with credentials
	if err := conn.Bind(s.config.ActiveDirectory.Username, s.config.ActiveDirectory.Password); err != nil {
		return nil, fmt.Errorf("failed to bind to AD: %w", err)
	}

	// Prepare search filter
	filter := s.config.ActiveDirectory.Filter
	if filter == "" {
		filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	}

	// Define attributes to retrieve
	attributes := []string{
		"objectGUID", "userPrincipalName", "displayName", "mail", "sAMAccountName",
		"department", "title", "memberOf", "userAccountControl", "cn",
	}

	// Create search request with pagination
	pageSize := 100
	if s.config.SyncSettings.MaxUsers > 0 && s.config.SyncSettings.MaxUsers < pageSize {
		pageSize = s.config.SyncSettings.MaxUsers
	}

	searchRequest := ldap.NewSearchRequest(
		s.config.ActiveDirectory.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		pageSize, 60, false, // size limit, time limit, types only
		filter,
		attributes,
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search AD: %w", err)
	}

	var users []ADUser
	for _, entry := range sr.Entries {
		user := s.mapLDAPEntryToUser(entry)
		if user.Email != "" { // Only include users with email addresses
			users = append(users, user)

			// Respect max users limit
			if s.config.SyncSettings.MaxUsers > 0 && len(users) >= s.config.SyncSettings.MaxUsers {
				break
			}
		}
	}

	return users, nil
}

func (s *ADSyncService) mapLDAPEntryToUser(entry *ldap.Entry) ADUser {
	getAttr := func(name string) string {
		values := entry.GetAttributeValues(name)
		if len(values) > 0 {
			return values[0]
		}
		return ""
	}

	// Get email (try mail first, then userPrincipalName)
	email := getAttr("mail")
	if email == "" {
		email = getAttr("userPrincipalName")
	}

	// Parse user account control
	uacStr := getAttr("userAccountControl")
	isActive := !strings.Contains(uacStr, "2") // Simplified check for disabled accounts

	// Parse group memberships
	groups := entry.GetAttributeValues("memberOf")
	var cleanGroups []string
	for _, group := range groups {
		if strings.HasPrefix(group, "CN=") {
			parts := strings.Split(group, ",")
			if len(parts) > 0 {
				cn := strings.TrimPrefix(parts[0], "CN=")
				cleanGroups = append(cleanGroups, cn)
			}
		}
	}
	var objectGUID string
	rawGUID := entry.GetRawAttributeValue("objectGUID")
	if len(rawGUID) == 16 {
		// Parse the 16-byte slice into a UUID object
		parsedGUID, err := uuid.FromBytes(rawGUID)
		if err == nil {
			// Convert the UUID object to its standard string format
			objectGUID = parsedGUID.String()
		}
	}

	return ADUser{
		ObjectGUID:        objectGUID,
		UserPrincipalName: getAttr("userPrincipalName"),
		DisplayName:       getAttr("displayName"),
		Email:             strings.ToLower(email),
		Username:          getAttr("sAMAccountName"),
		Department:        getAttr("department"),
		Title:             getAttr("title"),
		Groups:            cleanGroups,
		IsActive:          isActive,
		Attributes: map[string]string{
			"cn":                 getAttr("cn"),
			"userPrincipalName":  getAttr("userPrincipalName"),
			"sAMAccountName":     getAttr("sAMAccountName"),
			"userAccountControl": getAttr("userAccountControl"),
		},
	}
}

func (s *ADSyncService) convertToAPIUsers(adUsers []ADUser) []APIUser {
	var apiUsers []APIUser
	for _, adUser := range adUsers {
		apiUser := APIUser{
			ExternalID:   adUser.ObjectGUID,
			Email:        adUser.Email,
			Name:         adUser.DisplayName,
			Username:     adUser.Username,
			Provider:     "ad_sync",
			ProviderID:   adUser.UserPrincipalName,
			IsActive:     adUser.IsActive,
			IsSyncedUser: true,
			SyncSource:   "ad_agent",
			ProviderData: map[string]interface{}{
				"objectGUID":        adUser.ObjectGUID,
				"userPrincipalName": adUser.UserPrincipalName,
				"sAMAccountName":    adUser.Username,
				"department":        adUser.Department,
				"title":             adUser.Title,
				"groups":            adUser.Groups,
				"attributes":        adUser.Attributes,
				"sync_timestamp":    time.Now().Unix(),
			},
		}
		apiUsers = append(apiUsers, apiUser)
	}
	return apiUsers
}

func (s *ADSyncService) syncToUserFlow(apiUsers []APIUser) error {
	// Prepare request
	syncRequest := SyncRequest{
		TenantID:  s.config.UserFlowAPI.TenantID,
		ClientID:  s.config.UserFlowAPI.ClientID,
		ProjectID: s.config.UserFlowAPI.ProjectID,
		Users:     apiUsers,
		DryRun:    s.config.SyncSettings.DryRun,
	}

	jsonData, err := json.Marshal(syncRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal sync request: %w", err)
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: s.config.UserFlowAPI.SkipVerify,
			},
		},
	}

	// Create request
	url := fmt.Sprintf("%s/uflow/ad/agent-sync", s.config.UserFlowAPI.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send sync request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync request failed with status %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Printf("UserFlow API response: %s", string(body))
	return nil
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}
