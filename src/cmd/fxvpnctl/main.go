// Command fxvpnctl is the L0 onboarding CLI for the Firefox VPN reserve
// transport (E-FXVPN design Part II II.2.1 onboarding path (a)): provision
// accounts into accounts.json, import refresh tokens, verify credentials
// end-to-end against the LIVE FxA/Guardian control plane WITHOUT ever
// opening a data-plane tunnel (red line 7 discipline: the tunnel talks to
// Mozilla only through the daemon engine; this tool touches the control
// plane on explicit owner action only).
//
//	fxvpnctl login  --store <accounts.json> --email E [--password PW] [--label L] [--code NNNNNN]
//	fxvpnctl import --store <accounts.json> --email E --refresh-token RT [--label L]
//	fxvpnctl list   --store <accounts.json>
//	fxvpnctl test   (--store <accounts.json> --email E) | --refresh-token RT
//
// The password may be supplied via env B4_FXVPN_PASSWORD instead of
// --password to keep it out of shell history and process listings.
//
// Exit codes: 0 ok; 1 error; 2 usage; 3 verification code required
// (rerun login/test with --code after reading the emailed code).
//
// SECRETS: tokens/passwords are never printed; output carries shapes,
// quota numbers and entitlement only (Account.Redacted contract).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

const usageText = `fxvpnctl - Firefox VPN reserve transport L0 onboarding

usage:
  fxvpnctl login  --store PATH --email E [--password PW] [--label L] [--code NNNNNN]
  fxvpnctl import --store PATH --email E --refresh-token RT [--label L]
  fxvpnctl list   --store PATH
  fxvpnctl test   (--store PATH --email E | --refresh-token RT)

password env fallback: B4_FXVPN_PASSWORD
exit codes: 0 ok, 1 error, 2 usage, 3 verification code required
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "login":
		err = cmdLogin(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "test":
		err = cmdTest(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usageText)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		var nc *needsCodeError
		if errors.As(err, &nc) {
			fmt.Fprintln(os.Stderr, "verification code required: read the emailed code and rerun with --code NNNNNN")
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type needsCodeError struct{ msg string }

func (e *needsCodeError) Error() string { return e.msg }

// ---- store helpers ---------------------------------------------------------------

func loadOrCreate(path string) (*fxvpn.AccountStore, *fxvpn.AccountsFile, error) {
	store := fxvpn.NewAccountStore(path)
	file, err := store.Load()
	if err == nil {
		return store, file, nil
	}
	if errors.Is(err, fxvpn.ErrStoreAbsent) {
		return store, &fxvpn.AccountsFile{}, nil
	}
	return nil, nil, err
}

// upsert merges acct into file by case-insensitive email: existing label is
// kept when the incoming one is empty; secrets are overwritten only when
// provided non-empty (engine parity: a refresh without a new token keeps
// the old one).
func upsert(file *fxvpn.AccountsFile, acct fxvpn.Account) {
	for i := range file.Accounts {
		a := &file.Accounts[i]
		if !strings.EqualFold(a.Email, acct.Email) {
			continue
		}
		if acct.Label != "" {
			a.Label = acct.Label
		}
		if acct.Password != "" {
			a.Password = acct.Password
		}
		if acct.RefreshToken != "" {
			a.RefreshToken = acct.RefreshToken
		}
		return
	}
	file.Accounts = append(file.Accounts, acct)
}

func findByEmail(file *fxvpn.AccountsFile, email string) (fxvpn.Account, bool) {
	for _, a := range file.Accounts {
		if strings.EqualFold(a.Email, email) {
			return a, true
		}
	}
	return fxvpn.Account{}, false
}

func pinPathFor(accountsPath string) string {
	dir := filepath.Dir(accountsPath)
	if dir == "." {
		return "pins.json"
	}
	return filepath.Join(dir, "pins.json")
}

func printJSON(v interface{}) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// ---- credential check (shared by login/test) -------------------------------------

// checkResult mirrors the GUI /api/fxvpn/accounts/test shape: quota numbers
// and entitlement surface, secrets never do.
type checkResult struct {
	OK           bool   `json:"ok"`
	NeedsCode    bool   `json:"needs_code,omitempty"`
	Error        string `json:"error,omitempty"`
	Class        string `json:"class,omitempty"`
	QuotaLeft    string `json:"quota_left,omitempty"`
	QuotaMax     string `json:"quota_max,omitempty"`
	QuotaReset   string `json:"quota_reset,omitempty"`
	Subscribed   *bool  `json:"subscribed,omitempty"`
	RefreshSaved bool   `json:"refresh_token_saved,omitempty"`
}

type creds struct {
	email        string
	password     string
	refreshToken string
	code         string
}

// verifyCredentials walks the FULL control-plane chain for one identity:
// FxA (refresh or login [+verify-code]) -> OAuth -> Guardian proxy pass
// (+ activate retry) -> entitlement probe. No data-plane traffic happens.
// Returns the (possibly rotated) refresh token for the caller to persist.
func verifyCredentials(ctx context.Context, cp *fxvpn.ControlPlane, c creds) (string, checkResult) {
	res := checkResult{}
	fxa := &fxvpn.FXA{CP: cp}
	var access, refreshToken string

	switch {
	case strings.TrimSpace(c.refreshToken) != "":
		tok, err := fxa.RefreshToken(ctx, c.refreshToken)
		if err != nil {
			res.Error, res.Class = err.Error(), fxvpn.Classify(err)
			return "", res
		}
		access = tok.AccessToken
		refreshToken = c.refreshToken
		if tok.RefreshToken != "" {
			refreshToken = tok.RefreshToken // server-side rotation
		}
	case strings.TrimSpace(c.password) != "":
		login, err := fxa.Login(ctx, c.email, c.password)
		if err != nil {
			res.Error, res.Class = err.Error(), fxvpn.Classify(err)
			return "", res
		}
		if !login.Verified {
			if strings.TrimSpace(c.code) == "" {
				res.NeedsCode, res.OK = true, true
				return "", res
			}
			if verr := fxa.VerifySession(ctx, login.SessionToken, c.code); verr != nil {
				res.Error, res.Class = verr.Error(), fxvpn.Classify(verr)
				return "", res
			}
		}
		tok, terr := fxa.OAuthToken(ctx, login.SessionToken)
		if terr != nil {
			res.Error, res.Class = terr.Error(), fxvpn.Classify(terr)
			return "", res
		}
		access = tok.AccessToken
		refreshToken = tok.RefreshToken
	default:
		res.Error = "either refresh_token or password required"
		return "", res
	}

	g := &fxvpn.Guardian{CP: cp}
	pass, perr := g.FetchProxyPass(ctx, access)
	if perr != nil {
		var ti *fxvpn.TokenInvalidError
		if errors.As(perr, &ti) {
			if _, aerr := g.Activate(ctx, access); aerr == nil {
				pass, perr = g.FetchProxyPass(ctx, access)
			}
		}
		if perr != nil {
			res.Error, res.Class = perr.Error(), fxvpn.Classify(perr)
			return "", res
		}
	}
	res.OK = true
	res.QuotaLeft, res.QuotaMax, res.QuotaReset = pass.QuotaLeft, pass.QuotaMax, pass.QuotaReset
	if ent, serr := g.FetchUserInfo(ctx, access); serr == nil {
		res.Subscribed = &ent.Subscribed
	}
	return refreshToken, res
}

// ---- subcommands ------------------------------------------------------------------

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", "/opt/etc/b4/fxvpn/accounts.json", "path to accounts.json")
	email := fs.String("email", "", "account email (required)")
	password := fs.String("password", os.Getenv("B4_FXVPN_PASSWORD"), "account password (default env B4_FXVPN_PASSWORD)")
	label := fs.String("label", "", "free-form account label")
	code := fs.String("code", "", "email verification code (after needs_code)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if strings.TrimSpace(*email) == "" || strings.TrimSpace(*password) == "" {
		fmt.Fprintln(os.Stderr, "--email and --password (or B4_FXVPN_PASSWORD) are required")
		os.Exit(2)
	}
	ctx := context.Background()
	cp, err := fxvpn.NewControlPlane(pinPathFor(*storePath))
	if err != nil {
		return err
	}
	refreshToken, res := verifyCredentials(ctx, cp, creds{
		email: *email, password: *password, code: *code,
	})
	if res.NeedsCode {
		printJSON(res)
		return &needsCodeError{"login needs the emailed verification code"}
	}
	if !res.OK {
		printJSON(res)
		return errors.New(res.Error)
	}

	store, file, err := loadOrCreate(*storePath)
	if err != nil {
		return err
	}
	upsert(file, fxvpn.Account{Email: *email, Label: *label, Password: *password, RefreshToken: refreshToken})
	if err := store.Save(file); err != nil {
		return err
	}
	res.RefreshSaved = true
	printJSON(res)
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", "/opt/etc/b4/fxvpn/accounts.json", "path to accounts.json")
	email := fs.String("email", "", "account email (required)")
	rt := fs.String("refresh-token", "", "FxA refresh token (required)")
	label := fs.String("label", "", "free-form account label")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if strings.TrimSpace(*email) == "" || strings.TrimSpace(*rt) == "" {
		fmt.Fprintln(os.Stderr, "--email and --refresh-token are required")
		os.Exit(2)
	}
	acct := fxvpn.Account{Email: *email, Label: *label, RefreshToken: *rt}
	if err := acct.Validate(); err != nil {
		return err
	}
	store, file, err := loadOrCreate(*storePath)
	if err != nil {
		return err
	}
	upsert(file, acct)
	if err := store.Save(file); err != nil {
		return err
	}
	fmt.Println("imported", acct.Redacted())
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", "/opt/etc/b4/fxvpn/accounts.json", "path to accounts.json")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	store := fxvpn.NewAccountStore(*storePath)
	file, err := store.Load()
	if err != nil {
		if errors.Is(err, fxvpn.ErrStoreAbsent) {
			fmt.Println("(no accounts yet - see `fxvpnctl login` / `fxvpnctl import`)")
			return nil
		}
		return err
	}
	for i := range file.Accounts {
		fmt.Printf("%d: %s\n", i+1, file.Accounts[i].Redacted())
	}
	return nil
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	storePath := fs.String("store", "/opt/etc/b4/fxvpn/accounts.json", "path to accounts.json")
	email := fs.String("email", "", "account email to test from the store")
	password := fs.String("password", os.Getenv("B4_FXVPN_PASSWORD"), "account password (default env B4_FXVPN_PASSWORD)")
	rt := fs.String("refresh-token", "", "test this refresh token instead of the store")
	code := fs.String("code", "", "email verification code (after needs_code)")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	c := creds{refreshToken: strings.TrimSpace(*rt), code: *code}
	if c.refreshToken == "" {
		if strings.TrimSpace(*email) == "" {
			fmt.Fprintln(os.Stderr, "provide --refresh-token or --store + --email")
			os.Exit(2)
		}
		_, file, err := loadOrCreate(*storePath)
		if err != nil {
			return err
		}
		acct, ok := findByEmail(file, *email)
		if !ok {
			return fmt.Errorf("account %q not found in store", *email)
		}
		c.email = acct.Email
		c.refreshToken = acct.RefreshToken
		c.password = *password
		if c.refreshToken == "" && c.password == "" {
			c.password = acct.Password // fall back to the stored password
		}
	} else if strings.TrimSpace(*password) != "" {
		c.password = "" // explicit token wins; never mix paths
	}

	ctx := context.Background()
	cp, err := fxvpn.NewControlPlane(pinPathFor(*storePath))
	if err != nil {
		return err
	}
	_, res := verifyCredentials(ctx, cp, c)
	if res.NeedsCode {
		printJSON(res)
		return &needsCodeError{"test needs the emailed verification code"}
	}
	if !res.OK {
		printJSON(res)
		return errors.New(res.Error)
	}
	printJSON(res)
	return nil
}
