package agentauth

import (
	"net/http"
	"strings"
)

const (
	HeaderAgentID        = "X-Agent-ID"
	HeaderCredential     = "X-Agent-Credential"
	HeaderBootstrapToken = "X-Agent-Bootstrap-Token"
)

func ApplyCredentialHeaders(req *http.Request, agentID string, credentialFunc func() string) {
	if req == nil {
		return
	}
	if agentID = strings.TrimSpace(agentID); agentID != "" {
		req.Header.Set(HeaderAgentID, agentID)
	}
	if credentialFunc == nil {
		return
	}
	if cred := strings.TrimSpace(credentialFunc()); cred != "" {
		req.Header.Set(HeaderCredential, cred)
	}
}
