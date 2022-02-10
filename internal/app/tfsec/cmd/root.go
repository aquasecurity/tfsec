package cmd

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/aquasecurity/defsec/metrics"
    "github.com/aquasecurity/defsec/rules"
    "github.com/aquasecurity/defsec/severity"
    "github.com/aquasecurity/tfsec/internal/pkg/config"
    "github.com/aquasecurity/tfsec/internal/pkg/custom"
    "github.com/aquasecurity/tfsec/internal/pkg/debug"
    "github.com/aquasecurity/tfsec/internal/pkg/legacy"
    _ "github.com/aquasecurity/tfsec/internal/pkg/rules"
    "github.com/aquasecurity/tfsec/internal/pkg/scanner"
    "github.com/aquasecurity/trivy-config-parsers/terraform/parser"
    "github.com/spf13/cobra"
)

func Root() *cobra.Command {
    return rootCmd
}

var rootCmd = &cobra.Command{
    Use:              "tfsec [directory]",
    Short:            "tfsec is a terraform security scanner",
    Long:             `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
    PersistentPreRun: prerun,
    RunE: func(_ *cobra.Command, args []string) error {

        var dir string
        var err error

        if len(args) == 1 {
            dir, err = filepath.Abs(args[0])
            if err != nil {
                failf("Error determining absolute path for provided path: %s", err)
            }
        } else {
            dir, err = os.Getwd()
            if err != nil {
                failf("Error determining current directory: %s", err)
            }
        }

        if dirInfo, err := os.Stat(dir); err != nil {
            failf("Error accessing provided path: %s", err)
        } else if !dirInfo.IsDir() {
            failf("The provided path is not a dir, exiting")
        }

        tfsecDir := fmt.Sprintf("%s/.tfsec", dir)

        if len(configFile) > 0 {
            tfsecConfig, err = loadConfigFile(configFile)
            if err != nil {
                return err
            }
        } else {
            jsonConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.json")
            yamlConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.yml")
            if _, err = os.Stat(jsonConfigFile); err == nil {
                tfsecConfig, err = loadConfigFile(jsonConfigFile)
                if err != nil {
                    return err
                }
            } else if _, err = os.Stat(yamlConfigFile); err == nil {
                tfsecConfig, err = loadConfigFile(yamlConfigFile)
                if err != nil {
                    return err
                }
            } else {
                tfsecConfig = &config.Config{}
            }
        }

        debug.Log("Loading custom checks...")
        if len(customCheckDir) == 0 {
            debug.Log("Using the default custom check folder")
            customCheckDir = tfsecDir
        }
        debug.Log("custom check directory set to %s", customCheckDir)
        err = custom.Load(customCheckDir)
        if err != nil {
            failf("There were errors while processing custom check files. %s", err)
        }
        debug.Log("Custom checks loaded")

        var filterResultsList []string
        if len(filterResults) > 0 {
            filterResultsList = strings.Split(filterResults, ",")
        }

        if len(tfvarsPaths) == 0 && unusedTfvarsPresent(dir) {
            _, _ = fmt.Fprintf(os.Stderr, "WARNING: A tfvars file was found but not automatically used. Did you mean to specify the --tfvars-file flag?\n")
        }

        totalTimer := metrics.Timer("timings", "total")
        totalTimer.Start()

        debug.Log("Starting parser...")
        p := parser.New(getParserOptions()...)
        if err := p.ParseDirectory(dir); err != nil {
            failf("Parse error: %s", err)
        }
        modules, _, err := p.EvaluateAll()
        if err != nil {
            failf("Parse error: %s", err)
        }

        // set up metrics
        parserMetrics := p.Metrics()
        metrics.Timer("timings", "disk i/o").SetValue(parserMetrics.Timings.DiskIODuration)
        metrics.Timer("timings", "parsing").SetValue(parserMetrics.Timings.ParseDuration)
        metrics.Counter("counts", "blocks").Set(parserMetrics.Counts.Blocks)
        metrics.Counter("counts", "modules").Set(parserMetrics.Counts.Modules)
        metrics.Counter("counts", "files").Set(parserMetrics.Counts.Files)
        metrics.Counter("results", "critical")
        metrics.Counter("results", "high")
        metrics.Counter("results", "medium")
        metrics.Counter("results", "low")

        debug.Log("Starting scanner...")
        results, err := scanner.New(getScannerOptions()...).Scan(modules)
        if err != nil {
            return fmt.Errorf("fatal error during scan: %w", err)
        }

        totalTimer.Stop()

        results = updateResultSeverity(results)
        results = removeExcludedResults(results, excludeDownloaded)
        if len(filterResultsList) > 0 {
            var filteredResult []rules.Result
            for _, result := range results {
                for _, ruleID := range filterResultsList {
                    if result.Rule().LongID() == ruleID {
                        filteredResult = append(filteredResult, result)
                    }
                }
            }
            results = filteredResult
        }

        for _, result := range results {
            metrics.Counter("results", strings.ToLower(string(result.Rule().Severity))).Increment(1)
        }

        if runStatistics {
            statistics := scanner.Statistics{}
            for _, result := range results {
                statistics = scanner.AddStatisticsCount(statistics, result)
            }
            statistics.PrintStatisticsTable()
            return nil
        }

        formats := strings.Split(format, ",")
        if err := output(outputFlag, formats, dir, results); err != nil {
            failf("Failed to write output: %s", err)
        }

        // Soft fail always takes precedence. If set, only execution errors
        // produce a failure exit code (1).
        if softFail {
            return nil
        }

        os.Exit(getDetailedExitCode(results))
        return nil
    },
}

func failf(format string, a ...interface{}) {
    fmt.Fprintf(os.Stderr, format+"\n", a...)
    os.Exit(1)
}

func getParserOptions() []parser.Option {
    var opts []parser.Option
    if allDirs {
        opts = append(opts, parser.OptionDoNotSearchTfFiles())
    }
    var validTfVarFiles []string
    if len(tfvarsPaths) > 0 {
        for _, tfvarsPath := range tfvarsPaths {
            tfvp, err := filepath.Abs(tfvarsPath)
            if err != nil {
                fmt.Println(err)
            }
            if _, err := os.Stat(tfvp); err == nil {
                validTfVarFiles = append(validTfVarFiles, tfvp)
            }
        }
        opts = append(opts, parser.OptionWithTFVarsPaths(validTfVarFiles))
    }
    var validExcludePaths []string
    if len(excludePaths) > 0 {
        for _, excludePath := range excludePaths {
            exP, err := filepath.Abs(excludePath)
            if err != nil {
                fmt.Println(err)
            }
            if _, err := os.Stat(exP); err == nil {
                validExcludePaths = append(validExcludePaths, exP)
            }
        }
        opts = append(opts, parser.OptionWithExcludePaths(validExcludePaths))
    }

    if !ignoreHCLErrors {
        opts = append(opts, parser.OptionStopOnHCLError())
    }

    if workspace != "" {
        opts = append(opts, parser.OptionWithWorkspaceName(workspace))
    }

    return opts
}

func getDetailedExitCode(results rules.Results) int {
    // If there are no failed rules, then produce a success exit code (0).
    if len(results) == 0 || len(results) == countPassedResults(results) {
        return 0
    }

    // If there are some failed rules but they are all of LOW severity, then
    // produce a special failure exit code (2).
    if allInfo(results) {
        return 2
    }

    // If there is any failed check of HIGH or WARNING severity, then
    // produce the regular failure exit code (1).
    return 1
}

func removeExcludedResults(results rules.Results, excludeDownloaded bool) rules.Results {
    var returnVal rules.Results
    for _, res := range results {
        if excludeDownloaded && strings.Contains(res.Range().GetFilename(), fmt.Sprintf("%c.terraform", os.PathSeparator)) {
            continue
        }
        returnVal = append(returnVal, res)
    }
    return returnVal
}

func getScannerOptions() []scanner.Option {
    var options []scanner.Option
    if includePassed {
        options = append(options, scanner.OptionIncludePassed())
    }
    if includeIgnored {
        options = append(options, scanner.OptionIncludeIgnored())
    }
    if workspace != "" {
        options = append(options, scanner.OptionWithWorkspaceName(workspace))
    }
    options = append(options, scanner.OptionWithSingleThread(singleThreadedMode))
    if stopOnCheckError {
        options = append(options, scanner.OptionStopOnErrors())
    }

    var allExcludedRuleIDs []string
    for _, exclude := range strings.Split(excludedRuleIDs, ",") {
        allExcludedRuleIDs = append(allExcludedRuleIDs, strings.TrimSpace(exclude))
    }
    allExcludedRuleIDs = mergeWithoutDuplicates(allExcludedRuleIDs, tfsecConfig.ExcludedChecks)

    options = append(options, scanner.OptionExcludeRules(allExcludedRuleIDs))
    return options
}

func mergeWithoutDuplicates(left, right []string) []string {
    var set = map[string]bool{}
    for _, x := range append(left, right...) {
        set[x] = true
    }
    var results []string
    for x := range set {
        results = append(results, x)
    }

    return results
}

func allInfo(results []rules.Result) bool {
    for _, res := range results {
        if res.Rule().Severity != severity.Low && res.Status() != rules.StatusPassed {
            return false
        }
    }
    return true
}

func updateResultSeverity(results []rules.Result) []rules.Result {
    overrides := tfsecConfig.SeverityOverrides

    if len(overrides) == 0 {
        return results
    }

    var overriddenResults []rules.Result
    for _, res := range results {
        for code, sev := range overrides {
            if res.Rule().LongID() == code || legacy.FindID(res.Rule().LongID()) == code {
                overrides := rules.Results([]rules.Result{res})
                override := res.Rule()
                override.Severity = severity.Severity(sev)
                overrides.SetRule(override)
                res = overrides[0]
            }
        }
        overriddenResults = append(overriddenResults, res)
    }

    return overriddenResults
}

func loadConfigFile(configFilePath string) (*config.Config, error) {
    debug.Log("loading config file %s", configFilePath)
    return config.LoadConfig(configFilePath)
}

func countPassedResults(results []rules.Result) int {
    passed := 0

    for _, res := range results {
        if res.Status() == rules.StatusPassed {
            passed++
        }
    }

    return passed
}

func unusedTfvarsPresent(checkDir string) bool {
    glob := fmt.Sprintf("%s/*.tfvars", checkDir)
    debug.Log("checking for tfvars files using glob: %s", glob)
    if matches, err := filepath.Glob(glob); err == nil && len(matches) > 0 {
        return true
    }
    return false
}
