package model

type tlsType struct {
	value uint8
	name  string
}

var tlsTypes = []tlsType{
	{value: 1, name: "ClientHello"},
	{value: 2, name: "ServerHello"},
	{value: 4, name: "OtherHandshake"},
	{value: 8, name: "ChangeCipher"},
	{value: 16, name: "Alert"},
	{value: 32, name: "AppData"},
}

func tlsTypesToStrings(bitfield uint8) []string {
	var values []string
	for _, flag := range tlsTypes {
		if bitfield&flag.value != 0 {
			values = append(values, flag.name)
		}
	}
	return values
}
