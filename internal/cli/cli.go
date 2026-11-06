// Package cli is the recon command line: flags, validation, the
// authorisation prompt, signals and exit codes.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rafaelh/recon/internal/config"
	"github.com/rafaelh/recon/internal/egress"
	"github.com/rafaelh/recon/internal/engagement"
	"github.com/rafaelh/recon/internal/findings"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/output"
	"github.com/rafaelh/recon/internal/report"
	"github.com/rafaelh/recon/internal/run"
	"github.com/rafaelh/recon/internal/stages/asn"
	"github.com/rafaelh/recon/internal/stages/dns"
	"github.com/rafaelh/recon/internal/stages/orgpivot"
	"github.com/rafaelh/recon/internal/stages/ports"
	"github.com/rafaelh/recon/internal/stages/providerranges"
	"github.com/rafaelh/recon/internal/stages/risk"
	"github.com/rafaelh/recon/internal/stages/shodan"
	"github.com/rafaelh/recon/internal/stages/subdomains"
	"github.com/rafaelh/recon/internal/stages/web"
)

// Deps are the collaborators of Execute, replaceable in tests.
type Deps struct {
	Stages        []run.Stage // in registry order
	Files         []output.File
	Egress        egress.Options
	Kinds         *kinds.Registry
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	StdinIsTTY    func() bool
	StdoutIsTTY   func() bool
	Clock         func() time.Time
	HandleSignals bool   // SIGINT, SIGTERM and SIGHUP cancel the run; a second one exits at once
	Version       string // shown by --version; empty means "devel"
}

// DefaultDeps returns the production dependencies.
func DefaultDeps() Deps {
	return Deps{
		Version: versionString(debug.ReadBuildInfo()),
		Stages:  defaultStages(), Files: output.Default(), Kinds: kinds.Default(),
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinIsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		StdoutIsTTY: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		Clock:       time.Now, HandleSignals: true,
	}
}

// defaultStages is the registry order (Spec 2 D25): sources first, then DNS,
// then the stages derived from what the sources found. Passes repeat, so
// late discoveries are picked up. The port sweep is last so that probing
// hostnames on 80 and 443 does not wait for a sweep that can take hours; the
// pass after it probes the ports it found (Spec 4 D1). Spec 5's email stage
// follows the DNS stages; storage follows the crawl so references found in the
// same pass are checked, and the Target stages run before the port sweep (Spec 5 D4).
func defaultStages() []run.Stage {
	sub := subdomains.New() // crtsh, wayback, commoncrawl, virustotal, securitytrails
	stages := []run.Stage{asn.New(), orgpivot.NewOrgASN(), orgpivot.NewCTOrg(), orgpivot.NewWhoisXML()}
	stages = append(stages, sub...)
	return append(stages,
		shodan.New(), providerranges.New(),
		dns.NewResolve(), dns.NewWildcard(nil), dns.NewPermutations(), dns.NewRDNS(), dns.NewIPOwner(),
		risk.NewEmail(), web.NewProbe(), web.NewCrawl(),
		risk.NewStorage(), risk.NewTakeover(), risk.NewSensitivePaths(), ports.New())
}

type options struct {
	domainsFile, excludeFile, engagement, redo, configPath string
	orgs, asns, cidrs, exclude                             []string
	passive, authorised, allowLarge, json, verbose         bool
}

const ackPrompt = "Confirm you are authorised to test this engagement's scope [y/N] "

// Execute runs recon with args and returns the process exit code.
func Execute(ctx context.Context, args []string, d Deps) int {
	if d.Kinds == nil {
		d.Kinds = kinds.Default()
	}
	if d.Version == "" {
		d.Version = develVersion // cobra only adds --version when Version is set
	}
	if d.Files == nil {
		d.Files = output.Default()
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.StdinIsTTY == nil {
		d.StdinIsTTY = func() bool { return false }
	}
	if d.StdoutIsTTY == nil {
		d.StdoutIsTTY = func() bool { return false }
	}
	if d.Stdin == nil {
		d.Stdin = strings.NewReader("")
	}
	var o options
	code := run.ExitOK
	cmd := newCommand(&o, d, func(c *cobra.Command, positional []string) {
		code = runCommand(ctx, c, positional, &o, d)
	})
	cmd.SetArgs(args)
	// Help and --version are written after the flags are parsed, so o.json is
	// already pflag's own reading of --json (any ParseBool spelling). JSON mode
	// keeps stdout to JSON events only.
	cmd.SetOut(writerFunc(func(p []byte) (int, error) {
		if o.json {
			return d.Stderr.Write(p)
		}
		return d.Stdout.Write(p)
	}))
	cmd.SetErr(d.Stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		// Parsing may have failed before --json was reached, so the args are
		// checked as well.
		return fail(newEmitter(d, o.json || argsWantJSON(args)), run.ExitInvalid, err)
	}
	return code
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// argsWantJSON reports whether args set --json to true, accepting every
// spelling pflag does. The last occurrence wins; "--" ends the flags.
func argsWantJSON(args []string) bool {
	on := false
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "--json" {
			on = true
		} else if v, ok := strings.CutPrefix(a, "--json="); ok {
			on, _ = strconv.ParseBool(v)
		}
	}
	return on
}

// fail reports a fatal error and the run's end, and returns code.
func fail(em report.Emitter, code int, err error) int {
	em.Emit(report.Event{Type: "error", Fields: map[string]any{"message": err.Error(), "exit_code": code}})
	em.Emit(report.Event{Type: "run_end", Fields: map[string]any{"exit_code": code}})
	return code
}

func stageNames(stages []run.Stage) []string {
	var names []string
	for _, s := range stages {
		names = append(names, s.Name())
	}
	return names
}

func newEmitter(d Deps, jsonMode bool) report.Emitter {
	if jsonMode {
		return report.NewJSON(d.Stdout, d.Clock)
	}
	return report.NewConsole(d.Stdout, d.StdoutIsTTY(), d.Clock).WithErr(d.Stderr)
}

func newCommand(o *options, d Deps, runFn func(*cobra.Command, []string)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon [domain...] [flags]",
		Short: "Passive-first reconnaissance of a target's domains, organisations and netblocks",
		Long: "recon records a target's hosts, IPs, web services, URLs and open ports, plus a severity-ranked\n" +
			"list of obvious exposures, using only third-party sources and the kind of contact any member of\n" +
			"the public could make. Results go to the console and to TXT/CSV files in an engagement directory.\n" +
			"Re-run with the same engagement (recon -e <name>) to resume.",
		Args:          cobra.ArbitraryArgs,
		Version:       d.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) error {
			runFn(c, args)
			return nil
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVarP(&o.domainsFile, "domains-file", "d", "", "file of root domains, one per line (# comments allowed)")
	f.StringArrayVar(&o.orgs, "org", nil, "organisation name (repeatable)")
	f.StringArrayVar(&o.asns, "asn", nil, "ASN, AS123 or 123; its announced netblocks become in scope (repeatable)")
	f.StringArrayVar(&o.cidrs, "cidr", nil, "netblock in CIDR notation (repeatable)")
	f.StringArrayVarP(&o.exclude, "exclude", "x", nil, "excluded hostname, *.wildcard or CIDR (repeatable)")
	f.StringVar(&o.excludeFile, "exclude-file", "", "file of exclusions, one per line (# comments allowed)")
	f.StringVarP(&o.engagement, "engagement", "e", "", "engagement name (default: derived from the first input)")
	f.BoolVar(&o.passive, "passive", false, "use third-party sources only; never contact target-owned systems")
	f.BoolVar(&o.authorised, "authorised", false, "confirm you are authorised to test this scope (alias --authorized)")
	f.BoolVar(&o.allowLarge, "allow-large-netblocks", false, "proceed even if in-scope IPv4 netblocks exceed --netblock-limit")
	f.StringVar(&o.redo, "redo", "", "re-perform every check of one stage (see the stage list below)")
	f.BoolVar(&o.json, "json", false, "emit one JSON event per line on stdout, with no styling or prompts")
	f.BoolVar(&o.verbose, "verbose", false, "show warnings, including failed checks")
	f.StringVar(&o.configPath, "config", "", "config file (default $XDG_CONFIG_HOME/recon/config.yaml, else ~/.config/recon/config.yaml)")
	f.Bool("version", false, "print the version and exit") // long-only: -v would be confused with --verbose
	config.RegisterFlags(f)
	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "authorized" {
			name = "authorised"
		}
		return pflag.NormalizedName(name)
	})

	cmd.SetVersionTemplate("recon {{.Version}}\n")
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		fmt.Fprintf(c.OutOrStdout(), "%s\n\n%s\n%s", c.Long, c.UsageString(), helpFooter(d.Stages))
	})
	return cmd
}

func helpFooter(stages []run.Stage) string {
	return `
Engagement name (a directory under --output-dir):
  Taken from -e if given, else from the first input, in this order of precedence: the first positional
  domain, else the first line of the domains file, else the first --org, else the first --asn, else the
  first --cidr. So naming depends on the order of your inputs. The name is lowercased and sanitised.

Configuration:
  Settings come from a YAML config file, RECON_* environment variables or flags; flags override
  environment variables, which override the file. The default config file is
  $XDG_CONFIG_HOME/recon/config.yaml (default ~/.config/recon/config.yaml).
  Environment variables are RECON_<SETTING> with dots as underscores, e.g. RECON_CONCURRENCY and
  RECON_RATE_PER_HOST. API keys are never flags: set keys.<source> in the config file or
  RECON_KEYS_<SOURCE> in the environment.

Findings and their default severities (fixed in code, not configurable; the summary lists high and medium):
` + findings.HelpTable() + `
Stages accepted by --redo: ` + strings.Join(stageNames(stages), ", ") + "\n"
}

func runCommand(ctx context.Context, cmd *cobra.Command, positional []string, o *options, d Deps) (code int) {
	em := newEmitter(d, o.json)
	bail := func(code int, err error) int { return fail(em, code, err) }

	settings, err := config.Load(cmd.Flags(), o.configPath)
	if err != nil {
		return bail(run.ExitInvalid, err)
	}
	red := config.NewRedactor(settings.KeyValues()...)
	em = report.WithRedactor(em, red)

	parsed, err := input.Parse(input.Raw{
		Domains: positional, DomainsFile: o.domainsFile, Orgs: o.orgs, ASNs: o.asns, CIDRs: o.cidrs,
		Exclude: o.exclude, ExcludeFile: o.excludeFile,
	})
	if err != nil {
		return bail(run.ExitInvalid, err)
	}
	var name string
	switch {
	case o.engagement != "":
		if err := input.ValidateEngagementName(o.engagement); err != nil {
			return bail(run.ExitInvalid, err)
		}
		name = o.engagement
	case parsed.Empty():
		return bail(run.ExitInvalid, errors.New("no inputs: give domains, --org, --asn or --cidr, or -e <engagement> to resume one"))
	default:
		if name, err = input.EngagementName(parsed.First); err != nil {
			return bail(run.ExitInvalid, err)
		}
	}
	if names := stageNames(d.Stages); o.redo != "" && !slices.Contains(names, o.redo) {
		return bail(run.ExitInvalid, fmt.Errorf("unknown stage %q for --redo (stages: %s)", o.redo, strings.Join(names, ", ")))
	}

	eng, err := engagement.Open(filepath.Join(settings.OutputDir, name), engagement.Options{Clock: d.Clock, Redactor: red})
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	engOpen := true
	defer func() {
		if engOpen {
			eng.Close() // an earlier error was already reported
		}
	}()

	if err := eng.MergeInputs(parsed); err != nil {
		return bail(run.ExitFatal, err)
	}
	stored, err := eng.Inputs()
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	if stored.Empty() {
		return bail(run.ExitInvalid, fmt.Errorf("engagement %s has no scope; give domains, --org, --asn or --cidr", name))
	}

	if err := acknowledge(eng, o, d); err != nil {
		return bail(run.ExitFatal, err)
	}

	if d.HandleSignals {
		var stop context.CancelFunc
		ctx, stop = handleSignals(ctx)
		defer stop()
	}

	eg := egress.New(d.Egress.WithSettings(settings, red))
	runner := run.New(run.Config{
		Engagement: eng, Settings: settings, Stages: d.Stages, Egress: eg, Emitter: em,
		Files: d.Files, Kinds: d.Kinds, Clock: d.Clock,
		Passive: o.passive, AllowLargeNetblocks: o.allowLarge, Verbose: o.verbose, Redo: o.redo,
	})
	code, err = runner.Run(ctx)
	if err != nil {
		return bail(code, err)
	}
	// Close before run_end so a failure to save state is the run's only outcome.
	engOpen = false
	if err := eng.Close(); err != nil {
		return bail(run.ExitFatal, err)
	}
	if code == run.ExitInterrupted {
		em.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": "interrupted; completed work is saved, re-run to continue"}})
	}
	em.Emit(report.Event{Type: "run_end", Fields: map[string]any{"exit_code": code}})
	return code
}

// acknowledge records the operator's authorisation: by flag, or once per
// engagement by prompt when there is a terminal (B14).
func acknowledge(eng *engagement.Engagement, o *options, d Deps) error {
	if o.authorised {
		return eng.SetAck()
	}
	if eng.Acked() || o.passive || o.json || !d.StdinIsTTY() {
		return nil
	}
	if !slices.ContainsFunc(d.Stages, func(s run.Stage) bool { return s.Contact() == run.Target }) {
		return nil
	}
	fmt.Fprint(d.Stderr, ackPrompt)
	line, _ := bufio.NewReader(d.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
		return eng.SetAck()
	}
	return nil
}

func handleSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
			return
		}
		<-ch
		os.Exit(run.ExitInterrupted)
	}()
	return ctx, func() { signal.Stop(ch); cancel() }
}
