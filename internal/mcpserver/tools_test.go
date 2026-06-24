package mcpserver

import "testing"

func TestToolRegistryCount(t *testing.T) {
	const expectedTools = 54

	if got := len(Tools()); got != expectedTools {
		t.Fatalf("tool registry count = %d, want %d", got, expectedTools)
	}
}

func TestMappingToolsRegistered(t *testing.T) {
	tools := Tools()
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool.Tool.Name] = true
	}

	for _, name := range []string{"cert_map_scan", "cert_map_parse_files", "cert_map_timeline"} {
		if !names[name] {
			t.Fatalf("tool %q is not registered", name)
		}
	}
}
