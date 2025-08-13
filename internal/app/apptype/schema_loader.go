// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

import (
	"fmt"
	"strings"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	TYPE  = "type"
	FIELD = "field"
	INDEX = "index"
)

func ReadStoreInfo(fileName string, inp []byte) (*starlark_type.StoreInfo, error) {
	storeInfo, err := LoadStoreInfo(fileName, inp)
	if err != nil {
		return nil, err
	}

	if err := validateStoreInfo(storeInfo); err != nil {
		return nil, err
	}

	return storeInfo, nil
}

func validateStoreInfo(storeInfo *starlark_type.StoreInfo) error {
	typeNames := map[string]bool{}
	for _, t := range storeInfo.Types {
		if _, ok := typeNames[t.Name]; ok {
			return fmt.Errorf("type %s already defined", t.Name)
		}
		typeNames[t.Name] = true

		fieldNames := map[string]bool{}
		for _, f := range t.Fields {
			if _, ok := fieldNames[f.Name]; ok {
				return fmt.Errorf("field %s already defined in type %s", f.Name, t.Name)
			}
			fieldNames[f.Name] = true
		}

		for _, i := range t.Indexes {
			for _, f := range i.Fields {
				split := strings.Split(f, ":")
				if len(split) > 2 {
					return fmt.Errorf("invalid index field %s in type %s", f, t.Name)
				}
				if len(split) == 2 {
					lower := strings.ToLower(split[1])
					if lower != "asc" && lower != "desc" {
						return fmt.Errorf("invalid index field %s in type %s", f, t.Name)
					}
				}
				if _, ok := fieldNames[split[0]]; !ok {
					return fmt.Errorf("index field %s not defined in type %s", split[0], t.Name)
				}
			}
		}
	}

	return nil
}

func LoadStoreInfo(fileName string, data []byte) (*starlark_type.StoreInfo, error) {
	definedTypes := make(map[string]starlark.Value)

	typeBuiltin := func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name starlark.String
		var fields, indexes *starlark.List
		if err := starlark.UnpackArgs(TYPE, args, kwargs, "name", &name, "fields", &fields, "indexes?", &indexes); err != nil {
			return nil, err
		}

		if indexes == nil {
			indexes = starlark.NewList([]starlark.Value{})
		}

		typeDict := starlark.StringDict{
			"name":    name,
			"fields":  fields,
			"indexes": indexes,
		}
		newType := starlarkstruct.FromStringDict(starlark.String(TYPE), typeDict)

		if _, ok := definedTypes[string(name)]; ok {
			return nil, fmt.Errorf("type %s already defined", name)
		}
		definedTypes[string(name)] = newType

		return newType, nil
	}

	builtins := starlark.StringDict{
		TYPE:                          starlark.NewBuiltin(TYPE, typeBuiltin),
		FIELD:                         starlark.NewBuiltin(FIELD, createFieldBuiltin),
		INDEX:                         starlark.NewBuiltin(INDEX, createIndexBuiltin),
		string(starlark_type.INT):     starlark.String(starlark_type.INT),
		string(starlark_type.STRING):  starlark.String(starlark_type.STRING),
		string(starlark_type.BOOLEAN): starlark.String(starlark_type.BOOLEAN),
		string(starlark_type.DICT):    starlark.String(starlark_type.DICT),
		string(starlark_type.LIST):    starlark.String(starlark_type.LIST),
	}

	thread := &starlark.Thread{
		Name:  fileName,
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) },
	}

	_, err := starlark.ExecFile(thread, fileName, data, builtins)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			fmt.Printf("Error loading app schema: %s\n", evalErr.Backtrace()) // TODO: log
		}
		return nil, fmt.Errorf("error loading app schema: %w", err)
	}

	return createStoreInfo(definedTypes, data)
}

func createStoreInfo(definedTypes map[string]starlark.Value, data []byte) (*starlark_type.StoreInfo, error) {
	types := make([]starlark_type.StoreType, 0, len(definedTypes))
	for _, t := range definedTypes {
		typeStruct, ok := t.(*starlarkstruct.Struct)
		if !ok {
			return nil, fmt.Errorf("invalid type definition: %s", t.String())
		}

		typeName, err := GetStringAttr(typeStruct, "name")
		if err != nil {
			return nil, err
		}

		fields, err := getFields(string(typeName), typeStruct, "fields")
		if err != nil {
			return nil, fmt.Errorf("error getting fields in type %s: %s", typeName, err)
		}
		indexes, err := getIndexes(string(typeName), typeStruct, "indexes")
		if err != nil {
			return nil, fmt.Errorf("error getting indexes in type %s: %s", typeName, err)
		}

		types = append(types, starlark_type.StoreType{
			Name:    string(typeName),
			Fields:  fields,
			Indexes: indexes,
		})
	}

	return &starlark_type.StoreInfo{
		Bytes: data,
		Types: types,
	}, nil
}

func getFields(typeName string, typeStruct *starlarkstruct.Struct, key string) ([]starlark_type.StoreField, error) {
	fieldsAttr, err := typeStruct.Attr(key)
	if err != nil {
		return nil, fmt.Errorf("error getting %s attribute in type %s: %s", key, typeName, err)
	}

	fields, ok := fieldsAttr.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("%s is not a list in type %s", key, typeName)
	}

	fieldsList := fields
	iter := fieldsList.Iterate()
	var val starlark.Value

	ret := make([]starlark_type.StoreField, 0, fields.Len())
	for iter.Next(&val) {
		fieldStruct, ok := val.(*starlarkstruct.Struct)
		if !ok {
			return nil, fmt.Errorf("invalid field definition: %s", val.String())
		}

		fieldName, err := GetStringAttr(fieldStruct, "name")
		if err != nil {
			return nil, err
		}

		fieldType, err := GetStringAttr(fieldStruct, "type")
		if err != nil {
			return nil, err
		}

		field := starlark_type.StoreField{
			Name: string(fieldName),
			Type: starlark_type.TypeName(fieldType),
		}

		defaultValue, err := fieldStruct.Attr("default")
		if err == nil { // Attr is present
			val, err := starlark_type.UnmarshalStarlark(defaultValue)
			if err != nil {
				return nil, fmt.Errorf("error unmarshalling default value for field %s in type %s: %s", fieldName, typeName, err)
			}
			field.Default = val
		}

		ret = append(ret, field)
	}

	return ret, nil
}

func getIndexes(typeName string, typeStruct *starlarkstruct.Struct, key string) ([]starlark_type.Index, error) {
	indexesAttr, err := typeStruct.Attr(key)
	if err != nil {
		return []starlark_type.Index{}, nil // no indexes
	}

	if indexesAttr == nil || indexesAttr == starlark.None {
		return []starlark_type.Index{}, nil
	}

	indexes, ok := indexesAttr.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("%s is not a list in type %s", key, typeName)
	}

	indexesList := indexes
	iter := indexesList.Iterate()
	var val starlark.Value

	ret := make([]starlark_type.Index, 0, indexes.Len())
	for iter.Next(&val) {
		indexStruct, ok := val.(*starlarkstruct.Struct)
		if !ok {
			return nil, fmt.Errorf("invalid index definition: %s", val.String())
		}

		fields, err := GetListStringAttr(indexStruct, "fields", false)
		if err != nil {
			return nil, err
		}

		unique, err := GetBoolAttr(indexStruct, "unique")
		if err != nil {
			return nil, err
		}

		ret = append(ret, starlark_type.Index{
			Fields: fields,
			Unique: unique,
		})
	}

	return ret, nil
}

func createFieldBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, fieldType starlark.String
	var defaultValue starlark.Value = starlark.None
	if err := starlark.UnpackArgs(FIELD, args, kwargs, "name", &name, "type", &fieldType, "default?", &defaultValue); err != nil {
		return nil, err
	}

	field := starlark.StringDict{
		"name": name,
		"type": fieldType,
	}

	if defaultValue != starlark.None {
		field["default"] = defaultValue
	}
	return starlarkstruct.FromStringDict(starlark.String(FIELD), field), nil
}

func createIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var fields *starlark.List
	var unique starlark.Bool = false
	if err := starlark.UnpackArgs(INDEX, args, kwargs, "fields", &fields, "unique?", &unique); err != nil {
		return nil, err
	}

	index := starlark.StringDict{
		"fields": fields,
		"unique": unique,
	}

	return starlarkstruct.FromStringDict(starlark.String(INDEX), index), nil
}
