package kinds

import (
	"encoding/json"
	"reflect"
	"testing"
)

// attrTypes are the attribute structs of every Of kind but finding.
var attrTypes = []any{
	HostnameAttrs{}, NetblockAttrs{}, ExcludedAttrs{}, ResolutionAttrs{}, UnresolvedAttrs{}, WildcardAttrs{},
	IPOwnerAttrs{}, IPHostnameAttrs{}, ProviderRangeAttrs{}, WebServiceAttrs{}, HTTPPortAttrs{}, URLAttrs{},
	OpenPortAttrs{}, TakeoverHTTPAttrs{}, StorageAttrs{}, StorageAccountAttrs{}, StorageObjectAttrs{},
	StorageRefAttrs{}, SensitiveHitAttrs{}, EmailPostureAttrs{},
}

// filled returns a value of t with every field set to a non-zero value.
func filled(t reflect.Type) reflect.Value {
	v := reflect.New(t).Elem()
	for i := range t.NumField() {
		f := v.Field(i)
		switch {
		case f.Type() == sizeType:
			f.SetString("42")
		case f.Kind() == reflect.String:
			f.SetString("s" + t.Field(i).Name)
		case f.Kind() == reflect.Int:
			f.SetInt(int64(7 + i))
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		case f.Kind() == reflect.Pointer:
			b := false // a set false must survive, unlike absence
			f.Set(reflect.ValueOf(&b))
		case f.Kind() == reflect.Slice:
			f.Set(reflect.ValueOf([]string{"a", "b"}))
		}
	}
	return v
}

// viaJSON decodes attrs as json.Unmarshal of the stored JSON.
func viaJSON(t reflect.Type, attrs map[string]any) any {
	p := reflect.New(t)
	b, _ := json.Marshal(attrs)
	_ = json.Unmarshal(b, p.Interface())
	return p.Elem().Interface()
}

// unknownPointers is a JSON-decoded value with its pointer fields nil: given a
// value of the wrong type, decode leaves a pointer unknown, JSON sets it to zero.
func unknownPointers(a any) any {
	v := reflect.New(reflect.TypeOf(a)).Elem()
	v.Set(reflect.ValueOf(a))
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.Pointer {
			f.Set(reflect.Zero(f.Type()))
		}
	}
	return v.Interface()
}

func direct(t reflect.Type, attrs map[string]any) any {
	p := reflect.New(t)
	decode(attrs, p.Interface())
	return p.Elem().Interface()
}

// The direct decoder must agree with JSON: for a full record, an empty one,
// and one whose values have the wrong types.
func TestDecodeMatchesJSON(t *testing.T) {
	wrong := map[string]any{}
	for _, a := range attrTypes {
		typ := reflect.TypeOf(a)
		if planFor(typ) == nil {
			t.Errorf("%s falls back to JSON: give its fields simple types", typ.Name())
		}
		full := encode(filled(typ).Interface())
		for name, attrs := range map[string]map[string]any{"full": full, "empty": {}} {
			if got, want := direct(typ, attrs), viaJSON(typ, attrs); !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: direct %+v, JSON %+v", typ.Name(), name, got, want)
			}
		}
		for k := range full {
			wrong[k] = map[string]any{"not": "a value"}
		}
		if got, want := direct(typ, wrong), unknownPointers(viaJSON(typ, wrong)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s wrong types: direct %+v, JSON %+v", typ.Name(), got, want)
		}
	}
	// Numbers that do not fit an int are skipped; a size may be either.
	odd := map[string]any{"port": 1.5, "size": 42.0, "status": "200"}
	for _, typ := range []reflect.Type{reflect.TypeFor[WebServiceAttrs](), reflect.TypeFor[SensitiveHitAttrs]()} {
		if got, want := direct(typ, odd), viaJSON(typ, odd); !reflect.DeepEqual(got, want) {
			t.Errorf("%s odd values: direct %+v, JSON %+v", typ.Name(), got, want)
		}
	}
	if got := direct(reflect.TypeFor[SensitiveHitAttrs](), map[string]any{"size": "65536+"}).(SensitiveHitAttrs); got.Size != "65536+" {
		t.Errorf("cut size = %q", got.Size)
	}
}

// Encoding stores what was set and leaves out what omitempty says is unset.
func TestEncodeRoundTrip(t *testing.T) {
	for _, a := range attrTypes {
		typ := reflect.TypeOf(a)
		v := filled(typ).Interface()
		if got := direct(typ, encode(v)); !reflect.DeepEqual(got, v) {
			t.Errorf("%s: round trip %+v, want %+v", typ.Name(), got, v)
		}
	}
	m := encode(WebServiceAttrs{URL: "https://a.example.com", Host: "a.example.com"})
	if _, ok := m["tls_self_signed"]; ok {
		t.Error("tls_self_signed is stored only when TLS was seen")
	}
	if m["status"] != 0.0 || m["port"] != 0.0 {
		t.Errorf("always-set numbers are stored even when zero: %v", m)
	}
}
