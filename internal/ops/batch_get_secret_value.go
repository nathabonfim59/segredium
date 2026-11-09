package ops

// Contract for BatchGetSecretValue (frozen by the orchestrator; the handler body is the
// implementer's job). Wire shapes follow botocore secretsmanager/2017-10-17/service-2.json.

type batchGetSecretValueInput struct {
	Filters      []*listFilter `json:"Filters"`
	MaxResults   *int64        `json:"MaxResults"`
	NextToken    *string       `json:"NextToken"`
	SecretIDList []*string     `json:"SecretIdList"`
}

type batchGetSecretValueOutput struct {
	SecretValues []getSecretValueOutput `json:"SecretValues"`
	NextToken    string                 `json:"NextToken,omitempty"`
	Errors       []apiErrorEntry        `json:"Errors,omitempty"`
}

// apiErrorEntry is the ErrorEntry shape of BatchGetSecretValue's Errors member.
type apiErrorEntry struct {
	SecretID  string `json:"SecretId"`
	ErrorCode string `json:"ErrorCode"`
	Message   string `json:"Message"`
}
