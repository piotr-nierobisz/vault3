package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var keyPattern = regexp.MustCompile(`^[A-Z0-9_]+_(STRING|INT|FLOAT|BOOL|DURATION)$`)

type Config struct {
	values map[string]any
}

// Start loads environment values in NAME_TYPE format and panics on invalid required entries.
func Start() *Config {
	required := REQUIRED_ENV_VARS
	loadDotEnv(".env")
	cfg := &Config{
		values: make(map[string]any),
	}

	for _, env := range os.Environ() {
		name, value, found := strings.Cut(env, "=")
		if !found {
			continue
		}

		// Only typed variables are loaded by config.
		if !keyPattern.MatchString(name) {
			continue
		}

		if strings.TrimSpace(value) == "" {
			panic(fmt.Sprintf("environment variable %s is empty", name))
		}

		parsed, err := parseTypedValue(name, value)
		if err != nil {
			panic(err)
		}
		cfg.values[name] = parsed
	}

	for _, key := range required {
		if !keyPattern.MatchString(key) {
			panic(fmt.Sprintf("required environment key %s does not follow NAME_TYPE format", key))
		}
		if _, ok := cfg.values[key]; !ok {
			panic(fmt.Sprintf("required environment variable %s is missing", key))
		}
	}

	return cfg
}

func loadDotEnv(path string) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		// .env is optional, environment may be injected by process manager.
		return
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if key == "" || value == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

func (c *Config) MustString(key string) string {
	v := c.mustGet(key)
	out, ok := v.(string)
	if !ok {
		panic(fmt.Sprintf("environment variable %s is not string", key))
	}
	return out
}

// LookupString returns a string config value and whether it was set. Use it for
// optional settings (e.g. the Mailgun credentials, which stay empty until the
// domain is wired up) where a missing value should degrade gracefully rather
// than panic like MustString. Values the app cannot run without are read with
// MustString and listed in REQUIRED_ENV_VARS so a missing one fails fast at
// startup.
func (c *Config) LookupString(key string) (string, bool) {
	if c == nil {
		return "", false
	}
	v, ok := c.values[key]
	if !ok {
		return "", false
	}
	out, ok := v.(string)
	return out, ok
}

func (c *Config) MustInt(key string) int {
	v := c.mustGet(key)
	out, ok := v.(int)
	if !ok {
		panic(fmt.Sprintf("environment variable %s is not int", key))
	}
	return out
}

func (c *Config) MustFloat(key string) float64 {
	v := c.mustGet(key)
	out, ok := v.(float64)
	if !ok {
		panic(fmt.Sprintf("environment variable %s is not float", key))
	}
	return out
}

func (c *Config) MustBool(key string) bool {
	v := c.mustGet(key)
	out, ok := v.(bool)
	if !ok {
		panic(fmt.Sprintf("environment variable %s is not bool", key))
	}
	return out
}

func (c *Config) MustDuration(key string) time.Duration {
	v := c.mustGet(key)
	out, ok := v.(time.Duration)
	if !ok {
		panic(fmt.Sprintf("environment variable %s is not duration", key))
	}
	return out
}

func (c *Config) mustGet(key string) any {
	if c == nil {
		panic("config is nil")
	}
	v, ok := c.values[key]
	if !ok {
		panic(fmt.Sprintf("environment variable %s is missing", key))
	}
	return v
}

func parseTypedValue(name string, raw string) (any, error) {
	switch inferType(name) {
	case "STRING":
		return raw, nil
	case "INT":
		out, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %s as int: %w", name, err)
		}
		return out, nil
	case "FLOAT":
		out, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %s as float: %w", name, err)
		}
		return out, nil
	case "BOOL":
		out, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %s as bool: %w", name, err)
		}
		return out, nil
	case "DURATION":
		out, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %s as duration: %w", name, err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported env type in %s", name)
	}
}

func inferType(name string) string {
	parts := strings.Split(name, "_")
	return parts[len(parts)-1]
}
