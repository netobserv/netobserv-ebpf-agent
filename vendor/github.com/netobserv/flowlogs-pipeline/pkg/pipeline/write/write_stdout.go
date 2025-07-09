/*
 * Copyright (C) 2021 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package write

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	jsonIter "github.com/json-iterator/go"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/sirupsen/logrus"
)

type writeStdout struct {
	formatter func(config.GenericMap) string
}

// Write writes a flow before being stored
func (t *writeStdout) Write(v config.GenericMap) {
	logrus.Tracef("entering writeStdout Write")
	fmt.Println(t.formatter(v))
}

func formatter(format string, reorder bool) func(config.GenericMap) string {
	switch format {
	case "json":
		jconf := jsonIter.Config{
			SortMapKeys: reorder,
		}.Froze()
		return func(v config.GenericMap) string {
			b, _ := jconf.Marshal(v)
			return string(b)
		}
	case "fields":
		return func(v config.GenericMap) string {
			var sb strings.Builder
			var order sort.StringSlice
			for fieldName := range v {
				order = append(order, fieldName)
			}
			order.Sort()
			w := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', 0)
			fmt.Fprintf(w, "\n\nFlow record at %s:\n", time.Now().Format(time.StampMilli))
			for _, field := range order {
				fmt.Fprintf(w, "%v\t=\t%v\n", field, v[field])
			}
			w.Flush()
			return sb.String()
		}
	}
	return func(v config.GenericMap) string {
		return fmt.Sprintf("%v", v)
	}
}

// NewWriteStdout create a new write
func NewWriteStdout(params config.StageParam) (Writer, error) {
	logrus.Debugf("entering NewWriteStdout")
	var format string
	if params.Write.Stdout != nil {
		format = params.Write.Stdout.Format
	}
	return &writeStdout{
		formatter: formatter(format, false),
	}, nil
}
