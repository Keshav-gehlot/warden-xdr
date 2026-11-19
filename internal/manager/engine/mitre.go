package engine

// MitreTechnique is a minimal ATT&CK reference used to label alerts.
type MitreTechnique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// Mitre covers the techniques referenced by the bundled ruleset plus common
// neighbours. Extend it as you add rules.
var Mitre = map[string]MitreTechnique{}

func init() {
	for _, t := range []MitreTechnique{
		{"T1595", "Active Scanning", "Reconnaissance"},
		{"T1595.002", "Vulnerability Scanning", "Reconnaissance"},
		{"T1190", "Exploit Public-Facing Application", "Initial Access"},
		{"T1133", "External Remote Services", "Initial Access"},
		{"T1078", "Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
		{"T1059", "Command and Scripting Interpreter", "Execution"},
		{"T1059.004", "Unix Shell", "Execution"},
		{"T1053.003", "Cron", "Execution, Persistence"},
		{"T1203", "Exploitation for Client Execution", "Execution"},
		{"T1136.001", "Create Account: Local Account", "Persistence"},
		{"T1098", "Account Manipulation", "Persistence"},
		{"T1098.004", "SSH Authorized Keys", "Persistence"},
		{"T1543.002", "Systemd Service", "Persistence, Privilege Escalation"},
		{"T1505.003", "Web Shell", "Persistence"},
		{"T1548.003", "Sudo and Sudo Caching", "Privilege Escalation, Defense Evasion"},
		{"T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"},
		{"T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion"},
		{"T1562.001", "Disable or Modify Tools", "Defense Evasion"},
		{"T1562.004", "Disable or Modify System Firewall", "Defense Evasion"},
		{"T1014", "Rootkit", "Defense Evasion"},
		{"T1564.001", "Hidden Files and Directories", "Defense Evasion"},
		{"T1110", "Brute Force", "Credential Access"},
		{"T1110.001", "Password Guessing", "Credential Access"},
		{"T1003.008", "/etc/passwd and /etc/shadow", "Credential Access"},
		{"T1046", "Network Service Discovery", "Discovery"},
		{"T1087.001", "Account Discovery: Local Account", "Discovery"},
		{"T1021.004", "Remote Services: SSH", "Lateral Movement"},
		{"T1071.001", "Web Protocols", "Command and Control"},
		{"T1105", "Ingress Tool Transfer", "Command and Control"},
		{"T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"},
		{"T1485", "Data Destruction", "Impact"},
		{"T1489", "Service Stop", "Impact"},
		{"T1499", "Endpoint Denial of Service", "Impact"},
		{"T1531", "Account Access Removal", "Impact"},
		{"T1565.001", "Stored Data Manipulation", "Impact"},
	} {
		Mitre[t.ID] = t
	}
}
