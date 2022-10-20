// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Decode decodes data from io reader to specified interfaces
/* Example:
var num1 uint16
var num2 uint32
// read the buffer 2 bytes and 4 bytes sequentially
// decode and output corresponding uint16 and uint32 number into num1 and num2 respectively
err := Decode(buffer, &num1, &num2)
*/
func Decode(buffer io.Reader, byteOrder binary.ByteOrder, outputs ...interface{}) error {
	var err error
	for _, out := range outputs {
		err = binary.Read(buffer, byteOrder, out)
		if err != nil {
			return fmt.Errorf("error in decoding data: %v", err)
		}
	}
	return nil
}
