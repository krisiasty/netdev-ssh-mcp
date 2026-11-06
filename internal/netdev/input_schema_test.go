package netdev

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// TestToolInputSchemaRequiredFields infers each tool's input schema the same
// way the MCP SDK does and checks that only genuinely mandatory parameters are
// marked required. Parameters with a default must carry omitempty, otherwise
// the SDK rejects calls that leave them out.
func TestToolInputSchemaRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		typ  reflect.Type
		want []string
	}{
		{name: "get_config", typ: reflect.TypeFor[GetConfigInput](), want: []string{"host"}},
		{name: "run_show_command", typ: reflect.TypeFor[RunShowCommandInput](), want: []string{"command", "host"}},
		{name: "run_ping", typ: reflect.TypeFor[RunPingInput](), want: []string{"destination", "host"}},
		{name: "run_traceroute", typ: reflect.TypeFor[RunTracerouteInput](), want: []string{"destination", "host"}},
		{name: "trust_host_key", typ: reflect.TypeFor[TrustHostKeyInput](), want: []string{"host"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema, err := jsonschema.ForType(tt.typ, &jsonschema.ForOptions{})
			if err != nil {
				t.Fatalf("jsonschema.ForType(%v) error = %v", tt.typ, err)
			}
			got := slices.Sorted(slices.Values(schema.Required))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("required = %v, want %v", got, tt.want)
			}
		})
	}
}
