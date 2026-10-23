package client

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/fxamacker/cbor/v2"
	ctapdiag "github.com/telesma-app/ctap/diagnostic"
)

const (
	diagnosticRedacted        = "[REDACTED]"
	diagnosticRedactedComment = "/" + diagnosticRedacted + "/"
)

type diagnosticMapValueKey struct {
	path string
	key  string
}

type diagnosticMessageSchema struct {
	typeInfo         reflect.Type
	subCommandParams map[uint64]reflect.Type
	mapValueTypes    map[diagnosticMapValueKey]reflect.Type
}

type diagnosticField struct {
	name       string
	goName     string
	path       string
	typeInfo   reflect.Type
	integerKey bool
	redact     bool
}

type diagnosticFormatter struct {
	decoder  cbor.DecMode
	encoder  cbor.EncMode
	diagnose cbor.DiagMode
	redacted []string

	subCommandParams map[uint64]reflect.Type
	mapValueTypes    map[diagnosticMapValueKey]reflect.Type
}

func renderDiagnostic(
	decoder cbor.DecMode,
	encoder cbor.EncMode,
	raw []byte,
	schema diagnosticMessageSchema,
) (ctapdiag.Message, uint64) {
	message := ctapdiag.Message{Bytes: len(raw)}
	if len(raw) == 0 {
		return message, 0
	}

	diagnosticMode, err := cbor.DiagOptions{ByteStringText: true}.DiagMode()
	if err != nil {
		message.Error = err.Error()
		return message, 0
	}

	formatter := diagnosticFormatter{
		decoder:          decoder,
		encoder:          encoder,
		diagnose:         diagnosticMode,
		subCommandParams: schema.subCommandParams,
		mapValueTypes:    schema.mapValueTypes,
	}

	var subCommand uint64

	message.Notation, subCommand, err = formatter.render(
		raw,
		schema.typeInfo,
		"",
		0,
	)
	if err != nil {
		message.Notation = ""
		message.Error = err.Error()

		return message, 0
	}

	slices.Sort(formatter.redacted)
	message.RedactedFields = slices.Compact(formatter.redacted)

	return message, subCommand
}

func (f *diagnosticFormatter) render(
	raw []byte,
	schema reflect.Type,
	path string,
	depth int,
) (string, uint64, error) {
	if len(raw) == 0 {
		return "", 0, fmt.Errorf("empty CBOR item")
	}

	switch raw[0] >> 5 {
	case 4:
		var values []cbor.RawMessage
		if err := f.decoder.Unmarshal(raw, &values); err != nil {
			return "", 0, err
		}

		childSchema := collectionElementType(schema)

		if len(values) == 0 {
			return "[]", 0, nil
		}

		var builder strings.Builder
		builder.WriteString("[\n")

		for index, value := range values {
			writeDiagnosticIndent(&builder, depth+1)

			notation, _, err := f.render(value, childSchema, path, depth+1)
			if err != nil {
				return "", 0, err
			}

			builder.WriteString(notation)

			if index < len(values)-1 {
				builder.WriteByte(',')
			}

			builder.WriteByte('\n')
		}

		writeDiagnosticIndent(&builder, depth)
		builder.WriteByte(']')

		return builder.String(), 0, nil
	case 5:
		return f.renderMap(raw, schema, path, depth)
	default:
		notation, err := f.diagnose.Diagnose(raw)
		return notation, 0, err
	}
}

func (f *diagnosticFormatter) renderMap(
	raw []byte,
	schema reflect.Type,
	path string,
	depth int,
) (string, uint64, error) {
	var values map[any]cbor.RawMessage
	if err := f.decoder.Unmarshal(raw, &values); err != nil {
		return "", 0, err
	}

	fields, err := f.fields(schema, path)
	if err != nil {
		return "", 0, err
	}

	var mapValueType reflect.Type
	if schema = indirectType(schema); schema != nil && schema.Kind() == reflect.Map {
		mapValueType = schema.Elem()
	}

	type entry struct {
		key       any
		keyCBOR   []byte
		valueCBOR cbor.RawMessage
		field     *diagnosticField
	}

	entries := make([]entry, 0, len(values))

	var subCommand uint64

	for key, value := range values {
		keyCBOR, err := f.encoder.Marshal(key)
		if err != nil {
			return "", 0, err
		}

		field := fields[string(keyCBOR)]
		if field != nil && field.goName == "SubCommand" {
			_ = f.decoder.Unmarshal(value, &subCommand)
		}

		entries = append(entries, entry{
			key:       key,
			keyCBOR:   keyCBOR,
			valueCBOR: value,
			field:     field,
		})
	}

	slices.SortFunc(entries, func(a, b entry) int {
		if len(a.keyCBOR) != len(b.keyCBOR) {
			return len(a.keyCBOR) - len(b.keyCBOR)
		}

		return bytes.Compare(a.keyCBOR, b.keyCBOR)
	})

	if len(entries) == 0 {
		return "{}", subCommand, nil
	}

	var builder strings.Builder
	builder.WriteString("{\n")

	for index, entry := range entries {
		writeDiagnosticIndent(&builder, depth+1)

		if entry.field != nil && entry.field.integerKey {
			if strings.ContainsRune(entry.field.name, '/') {
				return "", 0, fmt.Errorf("invalid ctapdiag name %q", entry.field.name)
			}

			builder.WriteByte('/')
			builder.WriteString(entry.field.name)
			builder.WriteString("/ ")
		}

		keyNotation, err := f.diagnose.Diagnose(entry.keyCBOR)
		if err != nil {
			return "", 0, err
		}

		builder.WriteString(keyNotation)
		builder.WriteString(": ")

		childSchema := mapValueType

		var valueNotation string

		if key, ok := entry.key.(string); ok {
			if variant := f.mapValueTypes[diagnosticMapValueKey{path: path, key: key}]; variant != nil {
				childSchema = variant
			}
		}

		if entry.field != nil {
			childSchema = entry.field.typeInfo
			if entry.field.goName == "SubCommandParams" {
				if variant := f.subCommandParams[subCommand]; variant != nil {
					childSchema = variant
				}
			}

			if entry.field.redact {
				valueNotation, err = f.redactedNotation(entry.valueCBOR, depth+1)
				if err != nil {
					return "", 0, err
				}

				f.redacted = append(f.redacted, entry.field.path)
			}
		}

		if valueNotation == "" {
			valueNotation, _, err = f.render(
				entry.valueCBOR,
				childSchema,
				fieldPath(path, entry.field),
				depth+1,
			)
			if err != nil {
				return "", 0, err
			}
		}

		builder.WriteString(valueNotation)

		if index < len(entries)-1 {
			builder.WriteByte(',')
		}

		builder.WriteByte('\n')
	}

	writeDiagnosticIndent(&builder, depth)
	builder.WriteByte('}')

	return builder.String(), subCommand, nil
}

func (f *diagnosticFormatter) redactedNotation(raw []byte, depth int) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("empty CBOR item")
	}

	switch raw[0] >> 5 {
	case 0:
		return diagnosticRedactedComment + " 0", nil
	case 1:
		return diagnosticRedactedComment + " -1", nil
	case 2:
		return "h'" + diagnosticRedactedComment + "'", nil
	case 3:
		return diagnosticRedactedComment + ` ""`, nil
	case 4:
		return redactedCollection('[', ']', depth), nil
	case 5:
		return redactedCollection('{', '}', depth), nil
	case 6:
		var tag cbor.RawTag
		if err := f.decoder.Unmarshal(raw, &tag); err != nil {
			return "", err
		}

		content, err := f.redactedNotation(tag.Content, depth)
		if err != nil {
			return "", err
		}

		return strconv.FormatUint(tag.Number, 10) + "(" + content + ")", nil
	case 7:
		switch raw[0] & 0x1f {
		case 20, 21:
			return diagnosticRedactedComment + " false", nil
		case 22:
			return diagnosticRedactedComment + " null", nil
		case 23:
			return diagnosticRedactedComment + " undefined", nil
		case 25, 26, 27:
			return diagnosticRedactedComment + " 0.0", nil
		default:
			return diagnosticRedactedComment + " simple(0)", nil
		}
	default:
		panic("unreachable")
	}
}

func redactedCollection(open, close byte, depth int) string {
	var builder strings.Builder
	builder.WriteByte(open)
	builder.WriteByte('\n')
	writeDiagnosticIndent(&builder, depth+1)
	builder.WriteString(diagnosticRedactedComment)
	builder.WriteByte('\n')
	writeDiagnosticIndent(&builder, depth)
	builder.WriteByte(close)

	return builder.String()
}

func writeDiagnosticIndent(builder *strings.Builder, depth int) {
	for range depth {
		builder.WriteString("  ")
	}
}

func (f *diagnosticFormatter) fields(schema reflect.Type, path string) (map[string]*diagnosticField, error) {
	result := make(map[string]*diagnosticField)
	if err := f.collectFields(indirectType(schema), path, result); err != nil {
		return nil, err
	}

	return result, nil
}

func (f *diagnosticFormatter) collectFields(
	schema reflect.Type,
	path string,
	result map[string]*diagnosticField,
) error {
	if schema == nil || schema.Kind() != reflect.Struct {
		return nil
	}

	for index := range schema.NumField() {
		fieldInfo := schema.Field(index)
		if fieldInfo.PkgPath != "" {
			continue
		}

		cborTag := fieldInfo.Tag.Get("cbor")
		cborParts := strings.Split(cborTag, ",")

		wireName := cborParts[0]
		if wireName == "-" {
			continue
		}

		if fieldInfo.Anonymous && wireName == "" {
			if err := f.collectFields(indirectType(fieldInfo.Type), path, result); err != nil {
				return err
			}

			continue
		}

		if wireName == "" {
			wireName = fieldInfo.Name
		}

		integerKey := slices.Contains(cborParts[1:], "keyasint")

		var wireKey any = wireName
		if integerKey {
			value, err := strconv.ParseInt(wireName, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid integer cbor tag %q on %s.%s", wireName, schema, fieldInfo.Name)
			}

			wireKey = value
		}

		encodedKey, err := f.encoder.Marshal(wireKey)
		if err != nil {
			return err
		}

		name, redact, err := diagnosticTag(fieldInfo)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", schema, fieldInfo.Name, err)
		}

		result[string(encodedKey)] = &diagnosticField{
			name:       name,
			goName:     fieldInfo.Name,
			path:       joinDiagnosticPath(path, fieldInfo.Name),
			typeInfo:   fieldInfo.Type,
			integerKey: integerKey,
			redact:     redact,
		}
	}

	return nil
}

func diagnosticTag(field reflect.StructField) (string, bool, error) {
	name := lowerCamel(field.Name)

	tag, ok := field.Tag.Lookup("ctapdiag")
	if !ok {
		return name, false, nil
	}

	parts := strings.Split(tag, ",")
	if parts[0] != "" && parts[0] != "-" {
		name = parts[0]
	}

	redact := false

	for _, option := range parts[1:] {
		switch option {
		case "":
		case "redact":
			redact = true
		default:
			return "", false, fmt.Errorf("unknown ctapdiag option %q", option)
		}
	}

	return name, redact, nil
}

func lowerCamel(name string) string {
	runes := []rune(name)
	if len(runes) == 0 || !unicode.IsUpper(runes[0]) {
		return name
	}

	end := 0
	for end < len(runes) && unicode.IsUpper(runes[end]) {
		end++
	}

	if end > 1 && end < len(runes) && unicode.IsLower(runes[end]) {
		end--
	}

	for index := range end {
		runes[index] = unicode.ToLower(runes[index])
	}

	return string(runes)
}

func indirectType(value reflect.Type) reflect.Type {
	for value != nil && value.Kind() == reflect.Pointer {
		value = value.Elem()
	}

	return value
}

func collectionElementType(value reflect.Type) reflect.Type {
	value = indirectType(value)
	if value == nil || (value.Kind() != reflect.Array && value.Kind() != reflect.Slice) {
		return nil
	}

	return value.Elem()
}

func fieldPath(parent string, field *diagnosticField) string {
	if field == nil {
		return parent
	}

	return field.path
}

func joinDiagnosticPath(parent, child string) string {
	if parent == "" {
		return child
	}

	return parent + "." + child
}
