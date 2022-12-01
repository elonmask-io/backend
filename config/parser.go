package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
)

var (
	ErrNoPtr       = errors.New("config must be a pointer")
	ErrNoStructPtr = errors.New("config must be a struct pointer")
)

// FromEnv does not support Slices, Arrays and Maps
func FromEnv(out interface{}) error {
	value := reflect.ValueOf(out)
	if value.Kind() != reflect.Ptr {
		return ErrNoPtr
	}
	elem := value.Elem()
	if elem.Kind() != reflect.Struct {
		return ErrNoStructPtr
	}

	return processStruct(elem)
}

func processStruct(structValue reflect.Value) error {
	structType := structValue.Type()
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Field(i)
		fieldType := structType.Field(i)

		tag := fieldType.Tag.Get("env")
		if !field.CanSet() || tag == "-" {
			continue
		}

		val := os.Getenv(tag)
		if err := setFieldContent(field, val); err != nil {
			return fmt.Errorf("tag '%s' caused error: %w", tag, err)
		}
	}
	return nil
}

func setFieldContent(field reflect.Value, val string) error {
	fieldType := field.Type()

	switch field.Kind() {
	case reflect.Invalid:
	case reflect.Bool:
		v, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("variable not set or invalid: %w", err)
		}

		field.SetBool(v)
	case reflect.String:
		field.SetString(val)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(val, 10, fieldType.Bits())
		if err != nil {
			return fmt.Errorf("variable not set or invalid: %w", err)
		}
		field.SetUint(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(val, 10, fieldType.Bits())
		if err != nil {
			return fmt.Errorf("variable not set or invalid: %w", err)
		}

		field.SetInt(v)
	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(val, fieldType.Bits())
		if err != nil {
			return fmt.Errorf("variable not set or invalid: %w", err)
		}

		field.SetFloat(v)
	case reflect.Struct:
		return processStruct(field)

	default:
		return errors.New("unknown field type")
	}
	return nil
}
