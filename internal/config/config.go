package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// replaceEnvVars replaces ${VAR} or $VAR in the string with the corresponding environment variable
func replaceEnvVars(input string) string {
	// Handle ${VAR} format
	for strings.Contains(input, "${") {
		start := strings.Index(input, "${")
		end := strings.Index(input, "}")
		if end == -1 {
			break
		}

		varName := input[start+2 : end]
		envValue := os.Getenv(varName)

		input = input[:start] + envValue + input[end+1:]
	}

	// Handle $VAR format
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		key := "$" + pair[0]
		if strings.Contains(input, key) {
			input = strings.ReplaceAll(input, key, pair[1])
		}
	}

	return input
}

// processConfigEnvVars recursively processes environment variables in the YAML
func processConfigEnvVars(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		node.Value = replaceEnvVars(node.Value)
	}
	if node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode {
		for _, n := range node.Content {
			if err := processConfigEnvVars(n); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadConfig reads the config file and returns a Config struct
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Read config file
	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Parse YAML into a yaml.Node
	var root yaml.Node
	if err := yaml.Unmarshal(file, &root); err != nil {
		return nil, err
	}

	// Process environment variables
	if err := processConfigEnvVars(&root); err != nil {
		return nil, err
	}

	// Decode the processed YAML into the config struct
	if err := root.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}
