package tester

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	pathReady     = "/ready"
	pathQuery     = "/loki/api/v1/query"
	queryArgLimit = "limit"
	queryArgQuery = "query"
)

var llog = logrus.WithField("component", "loki.Tester")

type Loki struct {
	BaseURL string
}

func (l *Loki) get(pathQuery string) (status int, body string, err error) {
	client := http.Client{}
	reqUrl := l.BaseURL + pathQuery
	llog.WithField("url", reqUrl).Debug("HTTP GET request")
	resp, err := client.Get(reqUrl)
	if err != nil {
		return 0, "", err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(bodyBytes), nil
}

func (l *Loki) Ready() error {
	status, body, err := l.get(pathReady)
	if err != nil {
		return fmt.Errorf("loki is not ready: %w", err)
	} else if status != http.StatusOK {
		return fmt.Errorf("loki is not ready (status %d): %s", status, body)
	}
	return nil
}

func (l *Loki) Query(limit int, labels map[string]string) (*LokiQueryResponse, error) {
	queryPath := strings.Builder{}
	queryPath.WriteString(fmt.Sprintf("%s?%s=%d", pathQuery, queryArgLimit, limit))
	if len(labels) > 0 {
		query := strings.Builder{}
		query.WriteByte('{')
		firstLabel := true
		for k, v := range labels {
			if firstLabel {
				firstLabel = false
			} else {
				query.WriteByte(',')
			}
			query.WriteString(k + `="` + v + `"`)
		}
		query.WriteByte('}')
		queryPath.WriteString("&" + queryArgQuery + "=" + url.QueryEscape(query.String()))
	}
	status, body, err := l.get(queryPath.String())
	if err != nil {
		return nil, fmt.Errorf("loki request error: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, body)
	}
	response := LokiQueryResponse{}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		llog.WithError(err).Debug(body)
		return nil, fmt.Errorf("can't unmarshal response body: %w", err)
	}
	return &response, nil
}

type LokiQueryResponse struct {
	Status string        `json:"status"`
	Data   LokiQueryData `json:"data"`
}

type LokiQueryData struct {
	Result []LokiQueryResult `json:"result"`
}

type LokiQueryResult struct {
	Stream map[string]string `json:"stream"`
	Values []FlowValue       `json:"values"`
}

type FlowValue []string

func (f FlowValue) FlowData() (map[string]interface{}, error) {
	if len(f) < 2 {
		return nil, fmt.Errorf("incorrect flow data: %v", f)
	}
	flow := map[string]interface{}{}
	if err := json.Unmarshal([]byte(f[1]), &flow); err != nil {
		return nil, fmt.Errorf("can't unmarshall JSON flow: %w", err)
	}
	return flow, nil
}
