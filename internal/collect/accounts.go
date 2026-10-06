package collect

import (
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type UserAccount struct {
	Name       string
	UID        string
	PrimaryGID string
	Home       string
	Shell      string
	Groups     string
	System     bool
	LastLogin  string
	LoggedIn   bool
}

type GroupAccount struct {
	Name    string
	GID     string
	Members string
	System  bool
}

type AccountInventory struct {
	Users           []UserAccount
	HumanUsers      []UserAccount
	Groups          []GroupAccount
	CurrentSessions []LoginSession
	Available       bool
	Hint            string
}

type LoginSession struct {
	Username string
	Terminal string
	Since    string
}

func Accounts() AccountInventory {
	passwd, passwdErr := os.ReadFile("/etc/passwd")
	groups, groupErr := os.ReadFile("/etc/group")
	if passwdErr != nil || groupErr != nil {
		return AccountInventory{
			Available: false,
			Hint:      "Benutzer- oder Gruppendaten konnten nicht gelesen werden.",
		}
	}

	groupNames := make(map[string]string)
	groupMembers := make(map[string][]string)
	accounts := make([]GroupAccount, 0)
	for _, line := range strings.Split(string(groups), "\n") {
		fields := strings.SplitN(line, ":", 4)
		if len(fields) != 4 || fields[0] == "" {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		members := nonEmptyFields(fields[3], ",")
		groupNames[fields[2]] = fields[0]
		groupMembers[fields[0]] = members
		accounts = append(accounts, GroupAccount{
			Name:    fields[0],
			GID:     fields[2],
			Members: strings.Join(members, ", "),
			System:  gid < 1000,
		})
	}

	users := make([]UserAccount, 0)
	lastLogins := readLastLogins()
	currentSessions := readCurrentSessions()
	loggedIn := make(map[string]bool)
	for _, session := range currentSessions {
		loggedIn[session.Username] = true
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.SplitN(line, ":", 7)
		if len(fields) != 7 || fields[0] == "" {
			continue
		}
		uid, uidErr := strconv.Atoi(fields[2])
		_, gidErr := strconv.Atoi(fields[3])
		if uidErr != nil || gidErr != nil {
			continue
		}
		memberships := make([]string, 0)
		for group, members := range groupMembers {
			for _, member := range members {
				if member == fields[0] {
					memberships = append(memberships, group)
					break
				}
			}
		}
		sort.Strings(memberships)
		primaryGroup := groupNames[fields[3]]
		if primaryGroup == "" {
			primaryGroup = fields[3]
		}
		users = append(users, UserAccount{
			Name:       fields[0],
			UID:        fields[2],
			PrimaryGID: primaryGroup,
			Home:       fields[5],
			Shell:      fields[6],
			Groups:     strings.Join(memberships, ", "),
			System:     uid < 1000,
			LastLogin:  lastLogins[fields[0]],
			LoggedIn:   loggedIn[fields[0]],
		})
	}

	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	humanUsers := make([]UserAccount, 0, len(users))
	for _, user := range users {
		uid, _ := strconv.Atoi(user.UID)
		if uid >= 1000 && interactiveShell(user.Shell) {
			humanUsers = append(humanUsers, user)
		}
	}
	return AccountInventory{Users: users, HumanUsers: humanUsers, Groups: accounts, CurrentSessions: currentSessions, Available: true}
}

func interactiveShell(shell string) bool {
	switch shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
		return false
	default:
		return shell != ""
	}
}

func readLastLogins() map[string]string {
	return readLastCommandLogins()
}

func readLastCommandLogins() map[string]string {
	result := make(map[string]string)
	output, err := exec.Command("last", "-F", "-w", "-n", "10000").Output()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[0] == "wtmp" || fields[0] == "reboot" || fields[0] == "shutdown" || fields[0] == "runlevel" {
			continue
		}
		if _, exists := result[fields[0]]; exists {
			continue
		}
		result[fields[0]] = strings.Join(fields[3:9], " ")
	}
	return result
}

func readCurrentSessions() []LoginSession {
	output, err := exec.Command("who").Output()
	if err != nil {
		return nil
	}
	sessions := make([]LoginSession, 0)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		sessions = append(sessions, LoginSession{Username: fields[0], Terminal: fields[1], Since: strings.Join(fields[2:], " ")})
	}
	return sessions
}

func nonEmptyFields(value, separator string) []string {
	fields := strings.Split(value, separator)
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			result = append(result, field)
		}
	}
	return result
}
