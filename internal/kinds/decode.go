package kinds

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// decode sets the fields of *dst from attrs, the map the store returns (JSON
// numbers as float64, lists as []any), as json.Unmarshal of the stored JSON
// would, except that a pointer field whose stored value has the wrong type
// stays nil (unknown) where JSON would point it at a zero value.
// Records are read on every pass, often by the thousand, so a struct
// whose fields are all of the simple types below is filled directly; any
// other destination goes through JSON, which is about ten times slower.
func decode(attrs map[string]any, dst any) {
	v := reflect.ValueOf(dst).Elem()
	if p := planFor(v.Type()); p != nil {
		for _, f := range p {
			if x, ok := attrs[f.name]; ok && x != nil {
				f.set(v.Field(f.index), x)
			}
		}
		return
	}
	if b, err := json.Marshal(attrs); err == nil {
		_ = json.Unmarshal(b, dst) // a mismatched field is skipped, the rest decode
	}
}

type field struct {
	name  string
	index int
	set   func(reflect.Value, any)
}

var plans sync.Map // reflect.Type -> []field, or nil to decode through JSON

func planFor(t reflect.Type) []field {
	if p, ok := plans.Load(t); ok {
		return p.([]field)
	}
	p := buildPlan(t)
	plans.Store(t, p)
	return p
}

var sizeType = reflect.TypeFor[Size]()

// buildPlan returns the fields of t, or nil if t is not a struct of fields
// decode can set directly.
func buildPlan(t reflect.Type) []field {
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []field
	for i := range t.NumField() {
		sf := t.Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if !sf.IsExported() || name == "" || name == "-" {
			return nil
		}
		set := setter(sf.Type)
		if set == nil {
			return nil
		}
		out = append(out, field{name: name, index: i, set: set})
	}
	return out
}

func setter(t reflect.Type) func(reflect.Value, any) {
	switch {
	case t == sizeType: // a number or a string
		return func(v reflect.Value, x any) {
			switch n := x.(type) {
			case string:
				v.SetString(n)
			case float64:
				v.SetString(strconv.FormatFloat(n, 'f', -1, 64))
			}
		}
	case t.Kind() == reflect.String:
		return func(v reflect.Value, x any) {
			if s, ok := x.(string); ok {
				v.SetString(s)
			}
		}
	case t.Kind() == reflect.Int:
		return func(v reflect.Value, x any) {
			if n, ok := x.(float64); ok && n == float64(int64(n)) {
				v.SetInt(int64(n))
			}
		}
	case t.Kind() == reflect.Bool:
		return func(v reflect.Value, x any) {
			if b, ok := x.(bool); ok {
				v.SetBool(b)
			}
		}
	case t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Bool:
		return func(v reflect.Value, x any) {
			if b, ok := x.(bool); ok {
				v.Set(reflect.ValueOf(&b))
			}
		}
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return func(v reflect.Value, x any) {
			list, ok := x.([]any)
			if !ok {
				return
			}
			out := make([]string, 0, len(list))
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					return // json.Unmarshal would fail the whole field
				}
				out = append(out, s)
			}
			v.Set(reflect.ValueOf(out))
		}
	}
	return nil
}
