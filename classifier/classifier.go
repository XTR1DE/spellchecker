package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

var (
	urlRegexp   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$`)
	emailRegexp = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	fileRegexp  = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\.` +
			`(?:py|sh|bash|zsh|fish|go|js|mjs|cjs|ts|tsx|jsx|` +
			`java|c|h|cc|cpp|cxx|hpp|cs|rs|php|rb|kt|kts|swift|sql|` +
			`html|htm|css|scss|sass|vue|svelte|json|yaml|yml|toml|` +
			`ini|cfg|conf|config|service|txt|md|log|csv|xml|` +
			`pem|crt|key|pdf|doc|docx|xls|xlsx|zip|tar|gz|7z|` +
			`exe|dll|so|bin)$`,
	)

	// CHANGED:
	// Здесь больше нет общего "word(" / "word.method(".
	//
	// Они были слишком широкими как generic candidate:
	// malloc(...), preg_match(...), foo(...), version(...)
	// и т.д.
	//
	// Конкретные language anchors всё равно проверяются
	// отдельно в isSyntaxCandidate().
	syntaxCandidateRegexp = regexp.MustCompile(
		`(?:` +
			`[A-Za-z_$][A-Za-z0-9_$]*\s*(?:=|\+=|-=|\*=|/=|:=)` +
			`|^\s*(?:if|elif|for|while|switch|try|catch|return|throw)\b` +
			`|^\s*(?:const|let|var|def|class|func|fn|function|public|private|protected)\b` +
			`|^\s*#\s*(?:include|define|if|ifdef|ifndef|elif|else|endif)\b` +
			`|^\s*<[/A-Za-z]` +
			`)`,
	)

	cveRegexp      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	ghsaRegexp     = regexp.MustCompile(`^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$`)
	hashAlgoRegexp = regexp.MustCompile(`^SHA-(?:1|224|256|384|512)$`)
	hashRegexp     = regexp.MustCompile(
		`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})$`,
	)
	ipRegexp          = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	numberRegexp      = regexp.MustCompile(`^\d+(?:\.\d+)?$`)
	versionRegexp     = regexp.MustCompile(`^\d+(?:\.\d+)+$`)
	httpVersionRegexp = regexp.MustCompile(`^(?:HTTP|HTTPS)/\d+(?:\.\d+)+$`)
	protocolRegexp    = regexp.MustCompile(`^(https?|ftp|ssh|tcp|udp|smtp|dns)$`)

	timeRegexp = regexp.MustCompile(
		`^\d{1,2}:\d{2}(?:am|pm)?$`,
	)

	dateTimeRegexp = regexp.MustCompile(
		`^[A-Z][a-z]+ \d{1,2}, \d{4}, \d{1,2}:\d{2}(?:am|pm)?(?: [A-Z]{2,5})?$`,
	)

	hostPortRegexp = regexp.MustCompile(
		`^[A-Za-z0-9._-]+:\d+$`,
	)

	// Этап 6A, уровень 1: безопасный inline detection только для сильных
	// имён вида write_test(), decode_complete(),
	// PyEnvCfg.write(), repo.index.diff(...), func.func(),
	// jwt.decode(...). Старый общий word( detector не возвращаем:
	// он задевал прозу вида something(.
	// Уровень 2 (слабое имя + сильный сигнал внутри скобок) здесь
	// НЕ реализуем: type("/var") должен остаться прозой, а
	// startswith("/var/www/static/") пока не является обязательным
	// положительным тестом. Поэтому якорь требует сильное имя:
	// либо qualified obj.method (цепочка через точку), либо
	// bare snake_case с underscore. Голое type( / startswith(
	// под него не подпадают.
	inlineStrongCallRegexp = regexp.MustCompile(
		`(?:[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+|[A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]+)\s*\(`,
	)

	// Короткие statements: только явный синтаксис вида
	// if (...) { ... } / return ...; / throw ...; .
	// Отдельное something(...) сильным не становится, содержимое
	// аргументов не анализируем.
	ifBlockStartRegexp = regexp.MustCompile(
		`(?m)^[ \t]*if[ \t]*\(`,
	)

	fencedCodeRegexp = regexp.MustCompile(
		"(?s)```[^\\r\\n]*\\r?\\n.*?```",
	)

	backtickRegexp = regexp.MustCompile(
		"(?s)`[^`]*`",
	)

	htmlCodeRegexp = regexp.MustCompile(
		`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)\s*>`,
	)
	phpBlockRegexp = regexp.MustCompile(
		`(?s)<\?(?:php|=).*?\?>`,
	)
)

type Request struct {
	Text string `json:"text"`
}

type Token struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Type  string  `json:"type"`
	Text  string  `json:"text"`
	Lemma *string `json:"lemma,omitempty"`
	IB    *bool   `json:"ib,omitempty"`
}

var lastTokens []Token

type CodeRange struct {
	Start int
	End   int
	Type  string
}

var (
	jsonLanguage = grammars.JsonLanguage()
	jsLanguage   = grammars.JavascriptLanguage()

	jsonParser = gotreesitter.NewParser(jsonLanguage)
	jsParser   = gotreesitter.NewParser(jsLanguage)
)

/*
LEXICAL ENRICHMENT (POST /check, NDJSON stream)

tokenize() по-прежнему возвращает только classifier-токены:
start/end/type/text. После него enrichWords() собирает все
токены с Type == "WORD", отправляет их одним POST-запросом на
Python-сервис и по мере поступления NDJSON-строк добавляет
lemma/ib к тем же токенам in place. start/end принадлежат
classifier и не меняются: lexical-сервис лишь эхом возвращает
переданные ему координаты для сопоставления.
*/

const lexicalURL = "http://127.0.0.1:8091/check"

var lexicalClient = &http.Client{Timeout: 60 * time.Second}

type lemmaRequest struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

type lemmaBatch struct {
	Words []lemmaRequest `json:"words"`
}

type lemmaResult struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Text  string  `json:"text"`
	Lemma *string `json:"lemma"`
	IB    *bool   `json:"ib"`
	Error string  `json:"error,omitempty"`
}

func enrichWords(tokens []Token) []Token {
	// Индексы только пункту WORD; CODE/URL/PATH/CVE и остальные
	// типы в lexical-сервис не отправляются и не изменяются.
	indexByStart := make(map[int]int)

	words := make([]lemmaRequest, 0)

	for i, token := range tokens {
		if token.Type != "WORD" {
			continue
		}

		indexByStart[token.Start] = i

		words = append(words, lemmaRequest{
			Start: token.Start,
			End:   token.End,
			Text:  strings.ToLower(token.Text),
		})
	}

	// WORD нет — HTTP-запрос не делаем.
	if len(words) == 0 {
		return tokens
	}

	payload, err := json.Marshal(lemmaBatch{Words: words})
	if err != nil {
		log.Printf("[LEXICAL] marshal words: %v", err)
		return tokens
	}

	req, err := http.NewRequest(
		http.MethodPost,
		lexicalURL,
		bytes.NewReader(payload),
	)
	if err != nil {
		log.Printf("[LEXICAL] build request: %v", err)
		return tokens
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := lexicalClient.Do(req)
	if err != nil {
		log.Printf("[LEXICAL] post %s: %v", lexicalURL, err)
		return tokens
	}

	defer resp.Body.Close()

	// 400 отдает JSON-объект {"status":"error"}, а не NDJSON:
	// построчно его разбирать нельзя.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		log.Printf(
			"[LEXICAL] status=%d body=%q",
			resp.StatusCode,
			string(body),
		)

		return tokens
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())

		if len(line) == 0 {
			continue
		}

		var result lemmaResult

		if err := json.Unmarshal(line, &result); err != nil {
			log.Printf("[LEXICAL] bad ndjson line: %v", err)
			continue
		}

		// Строка с error (например, пустой text) не несет
		// lemma/ib: оставляем токен без обогащения.
		if result.Error != "" {
			log.Printf(
				"[LEXICAL] word error start=%d end=%d: %s",
				result.Start,
				result.End,
				result.Error,
			)

			continue
		}

		i, ok := indexByStart[result.Start]
		if !ok {
			log.Printf(
				"[LEXICAL] unknown start=%d end=%d text=%q",
				result.Start,
				result.End,
				result.Text,
			)

			continue
		}

		// Стыковка по координатам classifier: start обязан
		// совпасть, end/text проверяем для безопасности.
		if tokens[i].End != result.End ||
			strings.ToLower(tokens[i].Text) != result.Text {

			log.Printf(
				"[LEXICAL] mismatch start=%d expected=(end=%d text=%q) got=(end=%d text=%q)",
				result.Start,
				tokens[i].End,
				tokens[i].Text,
				result.End,
				result.Text,
			)

			continue
		}

		tokens[i].Lemma = result.Lemma
		tokens[i].IB = result.IB
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[LEXICAL] stream read: %v", err)
	}

	return tokens
}

var tokenRegexp = regexp.MustCompile(
	`(?s)(?:` +

		"`[^`]*`" + `|` + // CODE в backticks

		`-----BEGIN [^-]+-----.*?-----END [^-]+-----` + `|` + // PEM

		`[A-Z][a-z]+ \d{1,2}, \d{4}, \d{1,2}:\d{2}(?:am|pm)?(?: [A-Z]{2,5})?` + `|` + // March 24, 2026, 11:30am UTC

		`\d{1,2}:\d{2}(?:am|pm)?` + `|` + // 1:36pm / 15:30

		`(?:HTTP|HTTPS)/\d+(?:\.\d+)+` + `|` + // HTTP/1.1

		`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+` + `|` + // URL

		`[^\s@]+@[^\s@]+\.[^\s@]+` + `|` + // EMAIL

		`CVE-\d{4}-\d{4,}` + `|` +

		`GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}` + `|` +

		`SHA-(?:1|224|256|384|512)` + `|` +

		`[0-9a-fA-F]{128}|[0-9a-fA-F]{96}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}` + `|` +

		`(?:\d{1,3}\.){3}\d{1,3}` + `|` +

		`[A-Za-z0-9._-]+:\d+` + `|` +

		`\d+(?:\.\d+)+` + `|` + // VERSION

		`[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)+` + `|` + // RELATIVE PATH
		`/[^\s]+` + `|` +

		`[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\.(?:py|sh|bash|zsh|fish|go|js|mjs|cjs|ts|tsx|jsx|` +
		`java|c|h|cc|cpp|cxx|hpp|cs|rs|php|rb|kt|kts|swift|sql|` +
		`html|htm|css|scss|sass|vue|svelte|json|yaml|yml|toml|` +
		`ini|cfg|conf|config|service|txt|md|log|csv|xml|` +
		`pem|crt|key|pdf|doc|docx|xls|xlsx|zip|tar|gz|7z|` +
		`exe|dll|so|bin)` + `|` +

		`\d+(?:\.\d+)?` + `|` + // NUMBER

		`[\p{L}]+(?:[-'][\p{L}]+)*` + `|` + // WORD

		`_+|[$@][\p{L}\p{N}_-]+` + // UNKNOWN-ish identifiers
		`)`,
)

func main() {
	http.HandleFunc("/tokenize", tokenizeHandler)
	http.HandleFunc("/tokens", tokensHandler)

	println("server started on 8090")

	http.ListenAndServe(":8090", nil)
}

func tokenizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request Request

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	lastTokens = enrichWords(tokenize(request.Text))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(lastTokens)
}

func tokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(lastTokens)
}

func tokenize(text string) []Token {
	protected := findCodeRanges(text)

	tokens := make([]Token, 0)

	matches := tokenRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		startByte := match[0]
		endByte := match[1]

		if isInsideCodeRange(startByte, endByte, protected) {
			continue
		}

		value := text[startByte:endByte]

		tokens = append(tokens, Token{
			Start: runePosition(text, startByte),
			End:   runePosition(text, endByte),
			Type:  classifyToken(value),
			Text:  value,
		})
	}

	for _, r := range protected {
		tokens = append(tokens, Token{
			Start: runePosition(text, r.Start),
			End:   runePosition(text, r.End),
			Type:  r.Type,
			Text:  text[r.Start:r.End],
		})
	}

	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].Start < tokens[j].Start
	})

	return tokens
}

func classifyToken(token string) string {
	if isCode(token) {
		return "CODE"
	}

	if isPEM(token) {
		return "PEM"
	}

	if isDateTime(token) {
		return "DATETIME"
	}

	if isTime(token) {
		return "TIME"
	}

	if isHTTPVersion(token) {
		return "HTTP_VERSION"
	}

	if isURL(token) {
		return "URL"
	}

	if isEmail(token) {
		return "EMAIL"
	}

	if isCVE(token) {
		return "CVE"
	}

	if isGHSA(token) {
		return "GHSA"
	}

	if isHashAlgo(token) {
		return "HASH_ALGO"
	}

	if isHash(token) {
		return "HASH"
	}

	if isIP(token) {
		return "IP"
	}

	if isHostPort(token) {
		return "HOST_PORT"
	}

	if isVersion(token) {
		return "VERSION"
	}

	if isPath(token) {
		return "PATH"
	}

	if isFile(token) {
		return "FILE"
	}

	if isProtocol(token) {
		return "PROTOCOL"
	}

	if isNumber(token) {
		return "NUMBER"
	}

	if isWord(token) {
		return "WORD"
	}

	return "UNKNOWN"
}

func isTime(s string) bool {
	return timeRegexp.MatchString(strings.ToLower(s))
}

func isDateTime(s string) bool {
	return dateTimeRegexp.MatchString(s)
}

func isPEM(s string) bool {
	return strings.HasPrefix(s, "-----BEGIN ") &&
		strings.Contains(s, "-----END ")
}

func isURL(s string) bool {
	return urlRegexp.MatchString(s)
}

func isFile(s string) bool {
	return fileRegexp.MatchString(s)
}

func isEmail(s string) bool {
	return emailRegexp.MatchString(s)
}

func isCVE(s string) bool {
	return cveRegexp.MatchString(s)
}

func isGHSA(s string) bool {
	return ghsaRegexp.MatchString(s)
}

func isHashAlgo(s string) bool {
	return hashAlgoRegexp.MatchString(s)
}

func isHash(s string) bool {
	return hashRegexp.MatchString(s)
}

func isHTTPVersion(s string) bool {
	return httpVersionRegexp.MatchString(s)
}

func isVersion(s string) bool {
	return versionRegexp.MatchString(s)
}

func isHostPort(s string) bool {
	if !hostPortRegexp.MatchString(s) {
		return false
	}

	// version:2, step:1 — это "ключ:номер" в прозе, а не host:port.
	// Реальные порты (8080, 443, 6379, 5432, 3000) — 2-5 цифр,
	// односимвольный порт почти наверняка нумерация в тексте.
	// Точку в хосте НЕ требуем: localhost:8080, redis:6379,
	// db:5432, server:443 должны остаться HOST_PORT.
	_, port, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}

	return len(port) >= 2 && len(port) <= 5
}

func isIP(s string) bool {
	if !ipRegexp.MatchString(s) {
		return false
	}

	parts := strings.Split(s, ".")

	for _, part := range parts {
		n, err := strconv.Atoi(part)

		if err != nil || n > 255 {
			return false
		}
	}

	return true
}

func isNumber(s string) bool {
	return numberRegexp.MatchString(s)
}

func isProtocol(s string) bool {
	return protocolRegexp.MatchString(strings.ToLower(s))
}

func isPath(s string) bool {
	if strings.HasPrefix(s, "/") {
		return !strings.HasPrefix(s, "//")
	}

	if !strings.Contains(s, "/") ||
		strings.Contains(s, "://") {
		return false
	}

	// TCP/IP, I/O, and/or, input/output — слово/слово в прозе,
	// а не относительный путь. Отсекаем только узкий denylist
	// частых английских связок, чтобы не потерять реальные
	// пути вида src/main, docs/readme, foo/bar.
	if isProseSlashWord(s) {
		return false
	}

	return true
}

// isProseSlashWord возвращает true только для известных
// прозаических связок вида слово/слово. Остальное (src/main,
// docs/readme, api/v1) по-прежнему считается PATH —
// консервативно в пользу recall путей.
func isProseSlashWord(s string) bool {
	switch strings.ToLower(s) {
	case
		"tcp/ip",
		"input/output",
		"i/o",
		"and/or",
		"on/off",
		"yes/no",
		"true/false":
		return true
	}

	return false
}

func isCode(s string) bool {
	return strings.HasPrefix(s, "`") &&
		strings.HasSuffix(s, "`")
}

func isWord(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || r == '-' || r == '\'' {
			continue
		}

		return false
	}

	return true
}

func runePosition(text string, bytePosition int) int {
	return len([]rune(text[:bytePosition]))
}

/*
findCodeRanges

CODE теперь определяется так:

 1. явные конструкции:
    ```...```
    `...`
    JSON
    <script>/<style>

2. ищем только вероятное НАЧАЛО кодовой конструкции;
3. отдаём остаток текста Tree-sitter;
4. Tree-sitter возвращает AST-узел с реальными границами;
5. вручную balance / ";" / "}" больше не вычисляем.

Если код в отчёте обрезан через отдельную строку "...",
эта строка используется как явная граница фрагмента.
*/
func debugPreview(s string) string {
	s = strings.TrimSpace(s)

	runes := []rune(s)

	if len(runes) > 250 {
		return string(runes[:250]) + "..."
	}

	return s
}

func findCodeRanges(text string) []CodeRange {
	var ranges []CodeRange

	// Сначала защищаем конструкции с явно известными границами.
	ranges = append(ranges, findFencedCodeRanges(text)...)
	ranges = append(ranges, findBacktickRanges(text)...)
	ranges = append(ranges, findJSONRanges(text)...)
	ranges = append(ranges, findHTMLRanges(text)...)
	ranges = append(ranges, findPHPBlockRanges(text)...)

	// Этап 6A, уровень 1: inline сильные вызовы вида write_test(),
	// PyEnvCfg.write(), repo.index.diff(...). Только сильное имя,
	// уровень 2 (анализ содержимого скобок) не делаем.
	ranges = append(ranges, findInlineStrongCallRanges(text, ranges)...)

	// Короткие statements: if (...) { ... } с сильным синтаксисом
	// внутри. Отдельный if (...) без {, ;, $, оператора CODE не даёт.
	ranges = append(ranges, findIfBlockRanges(text, ranges)...)

	// Только оставшийся текст отдаём структурному детектору.
	ranges = append(
		ranges,
		findStructuredCodeRanges(text, ranges)...,
	)

	return mergeCodeRanges(text, ranges)
}

func findFencedCodeRanges(text string) []CodeRange {
	var ranges []CodeRange

	matches := fencedCodeRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		value := text[match[0]:match[1]]

		codeType := "CODE"

		firstLineEnd := strings.IndexByte(value, '\n')

		if firstLineEnd >= 0 {
			firstLine := strings.ToLower(value[:firstLineEnd])

			if strings.Contains(firstLine, "json") {
				codeType = "JSON"
			}
		}

		ranges = append(ranges, CodeRange{
			Start: match[0],
			End:   match[1],
			Type:  codeType,
		})
	}

	return ranges
}

func findBacktickRanges(text string) []CodeRange {
	var ranges []CodeRange

	matches := backtickRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		ranges = append(ranges, CodeRange{
			Start: match[0],
			End:   match[1],
			Type:  "CODE",
		})
	}

	return ranges
}

/*
findJSONRanges

JSON всё ещё ищем отдельно.

Tree-sitter JSON хорошо валидирует именно готовый
JSON-фрагмент, но не должен разбирать весь отчёт.
*/
func findJSONRanges(text string) []CodeRange {
	var ranges []CodeRange

	candidates := findBracketRanges(text)

	for _, candidate := range candidates {
		value := text[candidate.Start:candidate.End]

		if isValidJSON(value) {
			candidate.Type = "JSON"

			ranges = append(ranges, candidate)
		}
	}

	return ranges
}

func findBracketRanges(text string) []CodeRange {
	var ranges []CodeRange

	stack := make([]byte, 0)
	start := -1

	var quote byte
	escape := false

	for i := 0; i < len(text); i++ {
		c := text[i]

		if quote != 0 {
			if escape {
				escape = false
				continue
			}

			if c == '\\' {
				escape = true
				continue
			}

			if c == quote {
				quote = 0
			}

			continue
		}

		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}

		if c == '{' || c == '[' {
			if len(stack) == 0 {
				start = i
			}

			stack = append(stack, c)
			continue
		}

		if c != '}' && c != ']' {
			continue
		}

		if len(stack) == 0 {
			continue
		}

		open := stack[len(stack)-1]

		if (open == '{' && c != '}') ||
			(open == '[' && c != ']') {

			stack = stack[:0]
			start = -1

			continue
		}

		stack = stack[:len(stack)-1]

		if len(stack) == 0 && start >= 0 {
			ranges = append(ranges, CodeRange{
				Start: start,
				End:   i + 1,
			})

			start = -1
		}
	}

	return ranges
}

func isValidJSON(text string) bool {
	tree, err := jsonParser.Parse([]byte(text))

	if err != nil || tree == nil {
		return false
	}

	root := tree.RootNode()

	if root == nil {
		return false
	}

	return !root.HasError()
}

/*
findInlineStrongCallRanges — этап 6A, только уровень 1.

Сильное имя + "(" уже достаточно: write_test(), decode_complete(),
PyEnvCfg.write(), repo.index.diff(...), func.func(), jwt.decode(...).

Слабое имя (type(, startswith() не трогаем: уровень 2 с анализом
содержимого скобок здесь не реализуем. type("/var") остаётся прозой.

Граница — балансировка скобок от "(" с учётом кавычек, максимум
до конца строки: inline вызов не должен перетекать на prose.
*/
func findInlineStrongCallRanges(text string, protected []CodeRange) []CodeRange {
	var ranges []CodeRange

	matches := inlineStrongCallRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		openEnd := match[1] // индекс сразу после "("
		closeEnd, ok := matchBalancedParens(text, openEnd)
		if !ok {
			continue
		}
		// Этап 6B: цепочка после сильного вызова:
		// tornado.ioloop.IOLoop.current().start() — matchBalancedParens
		// останавливается после current(), остаток .start() терялся.
		// Расширяем только уже найденный сильный вызов, новые слабые
		// something() сильными не становятся.
		closeEnd = extendInlineCallChain(text, closeEnd)
		if isInsideCodeRange(match[0], closeEnd, protected) {
			continue
		}
		if strings.Contains(text[match[0]:closeEnd], "\n") {
			continue
		}

		// Этап 8: контекстный оператор `await` перед уже
		// подтверждённым сильным вызовом.
		//
		// Tree-sitter для "await axios.post(url)" отдаёт один
		// expression_statement 0-21: await лежит внутри
		// await_expression вместе с вызовом. Диапазон же начинал
		// строиться с имени вызова, поэтому await оставался WORD.
		//
		// Расширение применяется ТОЛЬКО к уже подтверждённому
		// диапазону: новых кандидатов не появляется, поэтому prose
		// вида "await the results of the analysis" (без сильного
		// вызова) остаётся WORD.
		rangeStart := awaitContextStart(text, match[0])

		ranges = append(ranges, CodeRange{
			Start: rangeStart,
			End:   closeEnd,
			Type:  "CODE",
		})
	}

	return ranges
}

/*
awaitContextStart

Возвращает начало контекстного оператора `await`, если он стоит
непосредственно перед уже подтверждённым сильным вызовом на той же
строке. Иначе возвращает start без изменений.

Правила намеренно строгие:

  - между `await` и вызовом допустимы только пробелы и табуляции;
    перенос строки означает многострочную конструкцию, которую
    inline-детектор обрабатывать не должен;
  - `await` должен быть отдельным словом, поэтому "myawait axios..."
    не расширяется. Граница слова проверяется через
    isInlineNameChar.

`return`, `throw` и `new` здесь намеренно НЕ добавляются: они также
затрагивают общий language-agnostic детектор и требуют отдельной
проверки на prose.
*/
func awaitContextStart(text string, start int) int {
	const keyword = "await"

	if start <= 0 {
		return start
	}

	i := start

	for i > 0 && (text[i-1] == ' ' || text[i-1] == '\t') {
		i--
	}

	keywordStart := i - len(keyword)

	if keywordStart < 0 {
		return start
	}

	if text[keywordStart:i] != keyword {
		return start
	}

	// Граница слова слева: "myawait" не считается оператором.
	if keywordStart > 0 &&
		isInlineNameChar(text[keywordStart-1]) {

		return start
	}

	return keywordStart
}

/*
findIfBlockRanges — короткие явные statements.

Только if (...) { ... } с сильным синтаксисом внутри:
"{" после балансировки (...) плюс один из сигналов
";", "$", "~", "==", "!=", "->", "::", "return", "throw".

Голый if (...) без "{" CODE не даёт. Проза вида
"if the value is invalid" / "if (x) may appear" не подходит:
нет баланса (...) + "{". Универсальный if (...)->CODE не делаем.
*/
func findIfBlockRanges(text string, protected []CodeRange) []CodeRange {
	var ranges []CodeRange

	matches := ifBlockStartRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		condEnd, ok := matchBalancedParens(text, match[1])
		if !ok {
			continue
		}
		i := condEnd
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= len(text) || text[i] != '{' {
			continue
		}
		blockEnd, ok := matchBalancedBraces(text, i+1)
		if !ok {
			continue
		}
		candidate := text[match[0]:blockEnd]
		if !hasStrongStatementSignal(candidate) {
			continue
		}
		if isInsideCodeRange(match[0], blockEnd, protected) {
			continue
		}
		ranges = append(ranges, CodeRange{
			Start: match[0],
			End:   blockEnd,
			Type:  "CODE",
		})
	}

	return ranges
}

// hasStrongStatementSignal требует явный кодовый синтаксис внутри
// if-блока. Проза с if/return словами без ; $ ~ операторов не проходит.
func hasStrongStatementSignal(s string) bool {
	if strings.Contains(s, ";") {
		return true
	}
	if strings.Contains(s, "$") {
		return true
	}
	if strings.Contains(s, "~") {
		return true
	}
	for _, op := range []string{"==", "!=", "->", "::"} {
		if strings.Contains(s, op) {
			return true
		}
	}
	lowered := " " + strings.ToLower(s) + " "
	for _, kw := range []string{" return ", " throw "} {
		if strings.Contains(lowered, kw) {
			return true
		}
	}

	return false
}

// matchBalancedBraces ищет закрывающую "}" для "{" на позиции openEnd-1.
// Возвращает индекс сразу после "}". Кавычки и экранирование учитываются,
// вложенные "{" ... "}" поддерживаются.
func matchBalancedBraces(text string, openEnd int) (int, bool) {
	depth := 1
	var quote byte
	escape := false

	for i := openEnd; i < len(text); i++ {
		c := text[i]

		if quote != 0 {
			if escape {
				escape = false
				continue
			}
			if c == '\\' {
				escape = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}

		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}

		if c == '{' {
			depth++
			continue
		}

		if c == '}' {
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}

	return 0, false
}

// extendInlineCallChain продолжает уже найденный сильный inline вызов:
// ".method(...)" / ".method" / ".method().next()". Отдельное слабое
// something() сильным не становится — стартовать цепочку можно только
// от range из findInlineStrongCallRanges.
func extendInlineCallChain(text string, end int) int {
	for end < len(text) {
		i := end
		// Пробелы между ")" и "." не разрешаем: цепочка вида
		// foo() . bar() в прозе подозрительна, оставляем строгий ".":
		if text[i] != '.' {
			return end
		}
		i++

		nameStart := i
		for i < len(text) && isInlineNameChar(text[i]) {
			i++
		}
		if i == nameStart {
			return end
		}

		j := i
		for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
			j++
		}
		if j < len(text) && text[j] == '(' {
			closeEnd, ok := matchBalancedParens(text, j+1)
			if !ok {
				return end
			}
			if strings.Contains(text[end:closeEnd], "\n") {
				return end
			}
			end = closeEnd
			continue
		}

		// ".attr" без скобок: tornado.ioloop.IOLoop.current — край
		// цепочки. Дальнейший ".start()" обработает следующая итерация.
		if strings.Contains(text[end:i], "\n") {
			return end
		}
		end = i
	}

	return end
}

func isInlineNameChar(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9')
}

// matchBalancedParens ищет закрывающую ")" для "(" на позиции openEnd-1.
// Возвращает индекс сразу после ")". Учитывает '...', "...", `...`
// и экранирование backslash. Вложенные "(" ... ")" поддерживаются.
func matchBalancedParens(text string, openEnd int) (int, bool) {
	depth := 1
	var quote byte
	escape := false

	for i := openEnd; i < len(text); i++ {
		c := text[i]

		if quote != 0 {
			if escape {
				escape = false
				continue
			}
			if c == '\\' {
				escape = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}

		if c == '"' || c == '\'' || c == '`' {
			quote = c
			continue
		}

		if c == '(' {
			depth++
			continue
		}

		if c == ')' {
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}

	return 0, false
}

func isInsideCodeRange(
	start,
	end int,
	ranges []CodeRange,
) bool {
	for _, r := range ranges {
		if start >= r.Start &&
			end <= r.End {

			return true
		}
	}

	return false
}

func isLineInsideProtectedRange(
	start int,
	end int,
	ranges []CodeRange,
) bool {
	for _, r := range ranges {
		if start >= r.Start && end <= r.End {
			return true
		}
	}

	return false
}

/*
mergeCodeRanges

Теперь merge работает только как объединитель уже найденных
AST/явных диапазонов.

Он больше НЕ определяет структуру кода.
*/
func mergeCodeRanges(
	text string,
	ranges []CodeRange,
) []CodeRange {
	if len(ranges) == 0 {
		return ranges
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start == ranges[j].Start {
			return ranges[i].End > ranges[j].End
		}

		return ranges[i].Start < ranges[j].Start
	})

	result := make([]CodeRange, 0, len(ranges))

	for _, current := range ranges {
		if current.Start >= current.End {
			continue
		}

		if len(result) == 0 {
			result = append(result, current)
			continue
		}

		last := &result[len(result)-1]

		// Полностью внутри предыдущего диапазона.
		if current.Start >= last.Start &&
			current.End <= last.End {

			if current.Type == "CODE" {
				last.Type = "CODE"
			}

			continue
		}

		// Пересекаются.
		if current.Start <= last.End {
			if current.End > last.End {
				last.End = current.End
			}

			if current.Type == "CODE" {
				last.Type = "CODE"
			}

			continue
		}

		// Между конструкциями только whitespace/comments
		// без пустой строки: пустая строка считается границей
		// между независимыми фрагментами и запрещает склейку.
		// Это точечный фикс C → Bash: "}\n\ncurl ..." больше не
		// объединяется в один CODE через "\n\n".
		gap := text[last.End:current.Start]
		if onlyWhitespaceOrComments(gap) &&
			!gapHasBlankLine(gap) {
			last.End = current.End

			if current.Type == "CODE" {
				last.Type = "CODE"
			}

			continue
		}

		result = append(result, current)
	}

	return result
}

func onlyWhitespaceOrComments(text string) bool {
	text = strings.TrimSpace(text)

	if text == "" {
		return true
	}

	for len(text) > 0 {
		if strings.HasPrefix(text, "//") {
			end := strings.IndexByte(text, '\n')

			if end == -1 {
				return true
			}

			text = strings.TrimSpace(text[end+1:])
			continue
		}

		if strings.HasPrefix(text, "/*") {
			end := strings.Index(text[2:], "*/")

			if end == -1 {
				return false
			}

			text = strings.TrimSpace(text[end+4:])
			continue
		}

		return false
	}

	return true
}

/*
gapHasBlankLine

Пустая строка между диапазонами означает визуальную границу
между независимыми фрагментами ("}\n\ncurl ...").

Комментарии границей не считаем: gap сюда приходит только если
onlyWhitespaceOrComments(gap) == true, пустую строку ищем по
переводу строк с учётом \r\n.
*/
func gapHasBlankLine(gap string) bool {
	normalized := strings.ReplaceAll(gap, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	lines := strings.Split(normalized, "\n")

	// Один перевод строки ("}\ncurl") — соседние строки,
	// склейка разрешена. Два и более ("\n\n") — пустая строка
	// между фрагментами, склейка запрещена.
	return len(lines) > 2
}

/*
----------------------------------------------------------------
STRUCTURED CODE DETECTION
----------------------------------------------------------------
*/

type codeLanguageSpec struct {
	Name      string
	Language  *gotreesitter.Language
	Anchors   []*regexp.Regexp
	NodeTypes map[string]struct{}
}

func nodeTypeSet(types ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(types))

	for _, t := range types {
		result[t] = struct{}{}
	}

	return result
}

var (
	jsVariableAnchor = regexp.MustCompile(
		`^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=`,
	)

	jsFunctionAnchor = regexp.MustCompile(
		`^\s*(?:export\s+)?(?:default\s+)?function\b`,
	)

	jsClassAnchor = regexp.MustCompile(
		`^\s*(?:export\s+)?(?:default\s+)?class\s+[A-Za-z_$][A-Za-z0-9_$]*`,
	)

	jsImportExportAnchor = regexp.MustCompile(
		`^\s*(?:import|export)\b`,
	)

	// JS return/throw statements.
	//
	// return_statement и throw_statement УЖЕ входят в JS NodeTypes
	// (см. codeLanguageSpecs), но anchor'а к ним не было, поэтому
	// "throw new Error(...)" и "return true;" до Tree-sitter не
	// доходили, хотя AST разбирает их безупречно.
	//
	// Правило намеренно узкое: только начало строки и только
	// ключевое слово. Всё остальное решает Tree-sitter:
	// проза вида "return to the previous section." anchor ловит,
	// но не является валидным JS и отбрасывается на HasError().
	jsReturnThrowAnchor = regexp.MustCompile(
		`^\s*(?:return|throw)\b`,
	)

	pythonDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:(?:async)\s+)?(?:def|class)\s+[A-Za-z_][A-Za-z0-9_]*`,
	)

	// Этап Python import: узкий anchor только для import /
	// from ... import ... . Общий assignment detector не вводим:
	// header = ... / version = 2 должны остаться прозой.
	// Дotted имена поддерживаем: import tornado.web, from a.b import c.
	pythonImportAnchor = regexp.MustCompile(
		`^\s*import\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)*\s*$`,
	)

	pythonFromImportAnchor = regexp.MustCompile(
		`^\s*from\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*\s+import\s+(?:\(.+\)|[A-Za-z_*][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_*][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)*)\s*$`,
	)

	// CHANGED:
	// Не разрешаем любой текст вида:
	// "if this is something:"
	// "for the following reason:"
	//
	// Для Python конструкции теперь отдельно описаны
	// характерные формы.
	pythonControlAnchor = regexp.MustCompile(
		`(?:` +
			`^\s*(?:if|elif|while)\s+.+:\s*$` +
			`|^\s*for\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s+in\s+.+:\s*$` +
			`|^\s*with\s+.+:\s*$` +
			`|^\s*(?:try|finally)\s*:\s*$` +
			`|^\s*except(?:\s+.+)?\s*:\s*$` +
			`|^\s*match\s+.+:\s*$` +
			`)`,
	)

	cPreprocessorAnchor = regexp.MustCompile(
		`^\s*#\s*(?:include|define|if|ifdef|ifndef|elif|else|endif)\b`,
	)

	cStructAnchor = regexp.MustCompile(
		`^\s*typedef\s+(?:struct|union|enum)\b`,
	)

	cFunctionAnchor = regexp.MustCompile(
		`^\s*(?:(?:static|inline|extern|const|unsigned|signed|long|short)\s+)*(?:void|char|short|int|long|float|double|size_t|bool)\s+[A-Za-z_][A-Za-z0-9_]*\s*\(`,
	)

	cppDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|static|inline|virtual|explicit|constexpr|const|unsigned|signed|long|short)\s+)*(?:class|struct|union|enum|namespace)\s+[A-Za-z_][A-Za-z0-9_]*`,
	)

	cppFunctionAnchor = regexp.MustCompile(
		`^\s*(?:(?:static|inline|virtual|explicit|constexpr|const|unsigned|signed|long|short)\s+)*(?:void|char|short|int|long|float|double|auto|bool)\s+[A-Za-z_][A-Za-z0-9_:<>]*\s*\(`,
	)

	csharpDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|internal|static|abstract|sealed|partial)\s+)*(?:class|struct|interface|enum|record)\s+[A-Za-z_][A-Za-z0-9_]*`,
	)

	csharpMethodAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|internal|static|abstract|sealed|async|virtual|override|partial)\s+)+[A-Za-z_][A-Za-z0-9_<>,\[\]?]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\(`,
	)

	javaDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|static|abstract|final|sealed)\s+)*(?:class|interface|enum|record)\s+[A-Za-z_][A-Za-z0-9_]*`,
	)

	javaMethodAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|static|abstract|final|synchronized|native)\s+)+[A-Za-z_][A-Za-z0-9_<>,\[\]?]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\(`,
	)

	goDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:package|import|func|type)\b`,
	)

	goVarConstAnchor = regexp.MustCompile(
		`^\s*(?:var|const)\s+[A-Za-z_][A-Za-z0-9_]*\s*=`,
	)

	rustDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:(?:pub|async|unsafe|const|extern)\s+)*(?:fn|struct|enum|impl|trait|use|mod)\b`,
	)

	rustLetAnchor = regexp.MustCompile(
		`^\s*let\s+[A-Za-z_][A-Za-z0-9_]*\s*=`,
	)

	phpOpenTagAnchor = regexp.MustCompile(
		`^\s*<\?(?:php|=)`,
	)

	phpFunctionAnchor = regexp.MustCompile(
		`^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(`,
	)

	phpClassAnchor = regexp.MustCompile(
		`^\s*(?:(?:abstract|final)\s+)?(?:class|interface|trait)\s+[A-Za-z_][A-Za-z0-9_]*`,
	)

	phpControlAnchor = regexp.MustCompile(
		`^\s*(?:if|elseif|for|foreach|while|switch|catch)\s*\([^)]*\)\s*\{`,
	)

	phpAssignmentAnchor = regexp.MustCompile(
		`^\s*\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*`,
	)

	phpStatementAnchor = regexp.MustCompile(
		`^\s*(?:return|throw|echo)\b.*;\s*$`,
	)

	rubyDeclarationAnchor = regexp.MustCompile(
		`^\s*(?:def|class|module)\s+[A-Za-z_][A-Za-z0-9_!?=]*`,
	)

	rubyRequireAnchor = regexp.MustCompile(
		`^\s*require\s+['"]`,
	)

	// Минимальный фикс этапа 5: раньше Ruby терялся уже на anchor.
	// rubyDeclarationAnchor (def/class/module) и rubyRequireAnchor
	// не покрывают обычные верхнеуровневые строки скрипта:
	// total = 0, CSV.foreach(...) do, puts total.
	// Поэтому isSyntaxCandidate() отбрасывал их до Tree-sitter,
	// а NodeTypes без assignment всё равно бы их отклонил.
	// Добавляем только два узких anchor, без расширения архитектуры.
	rubyAssignmentAnchor = regexp.MustCompile(
		`^\s*[a-z_][A-Za-z0-9_]*\s*=\s*[^=>\s]`,
	)

	rubyCallAnchor = regexp.MustCompile(
		`^\s*(?:[A-Z][A-Za-z0-9_]*\s*\.\s*[a-z_][A-Za-z0-9_!?]*|(?:puts|print|p|pp)\b)`,
	)

	htmlElementAnchor = regexp.MustCompile(
		`^\s*<[A-Za-z][A-Za-z0-9:-]*(?:\s+[^>]*)?>`,
	)

	// CHANGED:
	// Bash разделён на strong и weak команды.
	//
	// Strong-команды достаточно характерны для shell.
	bashStrongCommandAnchor = regexp.MustCompile(
		`^\s*(?:` +
			`sudo|cd|cp|mv|rm|mkdir|chmod|chown|` +
			`curl|wget|grep|sed|awk|find|tar|` +
			`git|go|python|python3|pip|pip3|npm|node|` +
			`ssh|scp|docker|kubectl|systemctl|` +
			`xargs|tee|touch|ln|ps|kill|killall|` +
			`whoami|pwd|which|whereis|uname|` +
			`printf|eval|exec|unset` +
			`)\b`,
	)

	// CHANGED:
	// Эти слова встречаются в обычном английском тексте.
	// Например:
	//
	// Test the following scenario...
	// Check the command...
	//
	// Поэтому они сами по себе не являются достаточным
	// доказательством Bash.
	bashWeakCommandAnchor = regexp.MustCompile(
		`^\s*(?:` +
			`cat|less|more|head|tail|sort|uniq|cut|tr|` +
			`env|printenv|export|source|read|` +
			`test|true|false|echo|command|id` +
			`)\b`,
	)

	bashShellAnchor = regexp.MustCompile(
		`^\s*(?:` +
			`[A-Za-z_][A-Za-z0-9_]*=` +
			`|\./` +
			`)`,
	)
)

var codeLanguageSpecs = []codeLanguageSpec{
	{
		Name:     "Bash",
		Language: grammars.BashLanguage(),
		Anchors: []*regexp.Regexp{
			bashStrongCommandAnchor,
			bashWeakCommandAnchor,
			bashShellAnchor,
		},
		NodeTypes: nodeTypeSet(
			"command",
			"pipeline",
			"redirected_statement",
		),
	},
	{
		Name:     "HTML",
		Language: grammars.HtmlLanguage(),
		Anchors: []*regexp.Regexp{
			htmlElementAnchor,
		},
		NodeTypes: nodeTypeSet(
			"element",
			"self_closing_tag",
			"start_tag",
		),
	},
	{
		Name:     "JavaScript",
		Language: grammars.JavascriptLanguage(),
		Anchors: []*regexp.Regexp{
			jsVariableAnchor,
			jsFunctionAnchor,
			jsClassAnchor,
			jsImportExportAnchor,
			jsReturnThrowAnchor,
		},
		NodeTypes: nodeTypeSet(
			"lexical_declaration",
			"variable_declaration",
			"function_declaration",
			"class_declaration",
			"import_statement",
			"export_statement",
			"if_statement",
			"for_statement",
			"for_in_statement",
			"while_statement",
			"do_statement",
			"switch_statement",
			"try_statement",
			"throw_statement",
			"return_statement",
			"expression_statement",
		),
	},

	{
		Name:     "TypeScript",
		Language: grammars.TypescriptLanguage(),
		Anchors: []*regexp.Regexp{
			jsVariableAnchor,
			jsFunctionAnchor,
			jsClassAnchor,
			jsImportExportAnchor,
		},
		NodeTypes: nodeTypeSet(
			"lexical_declaration",
			"variable_declaration",
			"function_declaration",
			"class_declaration",
			"interface_declaration",
			"enum_declaration",
			"import_statement",
			"export_statement",
			"if_statement",
			"for_statement",
			"for_in_statement",
			"while_statement",
			"do_statement",
			"switch_statement",
			"try_statement",
			"throw_statement",
			"return_statement",
			"expression_statement",
		),
	},

	{
		Name:     "Python",
		Language: grammars.PythonLanguage(),
		Anchors: []*regexp.Regexp{
			pythonDeclarationAnchor,
			pythonControlAnchor,
			pythonImportAnchor,
			pythonFromImportAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_definition",
			"class_definition",
			"if_statement",
			"for_statement",
			"while_statement",
			"try_statement",
			"with_statement",
			"match_statement",
			"import_statement",
			"import_from_statement",
			"return_statement",
			"assignment",
			"augmented_assignment",
		),
	},

	{
		Name:     "C",
		Language: grammars.CLanguage(),
		Anchors: []*regexp.Regexp{
			cPreprocessorAnchor,
			cStructAnchor,
			cFunctionAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_definition",
			"declaration",
			"struct_specifier",
			"enum_specifier",
			"type_definition",

			"preproc_include",
			"preproc_def",
			"preproc_function_def",
			"preproc_call",
			"preproc_if",
			"preproc_ifdef",
			"preproc_else",
			"preproc_elif",

			"if_statement",
			"for_statement",
			"while_statement",
			"switch_statement",
			"return_statement",
		),
	},

	{
		Name:     "C++",
		Language: grammars.CppLanguage(),
		Anchors: []*regexp.Regexp{
			cPreprocessorAnchor,
			cppDeclarationAnchor,
			cppFunctionAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_definition",
			"declaration",
			"class_specifier",
			"struct_specifier",
			"enum_specifier",
			"namespace_definition",
			"type_definition",

			"preproc_include",
			"preproc_def",
			"preproc_function_def",
			"preproc_call",
			"preproc_if",
			"preproc_ifdef",
			"preproc_else",
			"preproc_elif",

			"if_statement",
			"for_statement",
			"while_statement",
			"switch_statement",
			"return_statement",
		),
	},

	{
		Name:     "C#",
		Language: grammars.CSharpLanguage(),
		Anchors: []*regexp.Regexp{
			csharpDeclarationAnchor,
			csharpMethodAnchor,
		},
		NodeTypes: nodeTypeSet(
			"method_declaration",
			"class_declaration",
			"struct_declaration",
			"interface_declaration",
			"namespace_declaration",
			"enum_declaration",
			"if_statement",
			"for_statement",
			"foreach_statement",
			"while_statement",
			"switch_statement",
			"return_statement",
		),
	},

	{
		Name:     "Java",
		Language: grammars.JavaLanguage(),
		Anchors: []*regexp.Regexp{
			javaDeclarationAnchor,
			javaMethodAnchor,
		},
		NodeTypes: nodeTypeSet(
			"method_declaration",
			"class_declaration",
			"interface_declaration",
			"enum_declaration",
			"annotation_type_declaration",
			"if_statement",
			"for_statement",
			"enhanced_for_statement",
			"while_statement",
			"switch_expression",
			"return_statement",
		),
	},

	{
		Name:     "Go",
		Language: grammars.GoLanguage(),
		Anchors: []*regexp.Regexp{
			goDeclarationAnchor,
			goVarConstAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_declaration",
			"method_declaration",
			"type_declaration",
			"var_declaration",
			"const_declaration",
			"short_var_declaration",
			"if_statement",
			"for_statement",
			"expression_switch_statement",
			"type_switch_statement",
			"return_statement",
		),
	},

	{
		Name:     "Rust",
		Language: grammars.RustLanguage(),
		Anchors: []*regexp.Regexp{
			rustDeclarationAnchor,
			rustLetAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_item",
			"struct_item",
			"enum_item",
			"impl_item",
			"trait_item",
			"mod_item",
			"use_declaration",
			"let_declaration",
			"if_expression",
			"for_expression",
			"while_expression",
			"match_expression",
			"return_expression",
		),
	},

	{
		Name:     "PHP",
		Language: grammars.PhpLanguage(),
		Anchors: []*regexp.Regexp{
			phpFunctionAnchor,
			phpClassAnchor,
			phpControlAnchor,
			phpAssignmentAnchor,
			phpStatementAnchor,
		},
		NodeTypes: nodeTypeSet(
			"function_definition",
			"class_declaration",
			"interface_declaration",
			"trait_declaration",
			"namespace_definition",
			"if_statement",
			"for_statement",
			"foreach_statement",
			"while_statement",
			"switch_statement",
			"expression_statement",
			"return_statement",
			"throw_expression",
		),
	},

	{
		Name:     "Ruby",
		Language: grammars.RubyLanguage(),
		Anchors: []*regexp.Regexp{
			rubyDeclarationAnchor,
			rubyRequireAnchor,
			rubyAssignmentAnchor,
			rubyCallAnchor,
		},
		NodeTypes: nodeTypeSet(
			"method",
			"class",
			"module",
			"if",
			"while",
			"until",
			"for",
			"call",
			// Минимальный фикс этапа 5: без этих типов Tree-sitter
			// подтверждал только require/call, а total = 0 / store = []
			// отбрасывались в findStrongNodeAtOffset.
			"assignment",
			"operator_assignment",
		),
	},
}

func findStructuredCodeRanges(
	text string,
	protected []CodeRange,
) []CodeRange {
	var ranges []CodeRange

	lines := strings.SplitAfter(text, "\n")

	lineStarts := make([]int, len(lines))

	offset := 0

	for i, line := range lines {
		lineStarts[i] = offset
		offset += len(line)
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		raw := strings.TrimSpace(line)

		if raw == "" {
			continue
		}

		// CHANGED:
		// Candidate теперь является только дешёвым предварительным
		// фильтром. Само решение о том, похожа ли строка на конкретный
		// язык, всё равно принимается через его anchor ниже.
		if !isSyntaxCandidate(raw) {
			continue
		}

		if isLineInsideProtectedRange(
			lineStarts[i],
			lineStarts[i]+len(line),
			protected,
		) {
			continue
		}

		startInLine := strings.Index(line, raw)

		if startInLine < 0 {
			continue
		}

		start := lineStarts[i] + startInLine

		for _, spec := range codeLanguageSpecs {
			matched := matchesCodeAnchor(raw, spec.Anchors)

			log.Printf(
				"[ANCHOR CHECK] language=%s matched=%v text=%q",
				spec.Name,
				matched,
				debugPreview(raw),
			)

			if !matched {
				continue
			}

			// CHANGED:
			// Слабые Bash-команды ("test", "echo", "cat", "id" ...)
			// требуют дополнительного технического сигнала.
			if spec.Name == "Bash" &&
				bashWeakCommandAnchor.MatchString(raw) &&
				!hasCodeSignal(raw) {

				log.Printf(
					"[BASH SKIP WEAK] text=%q reason=no-code-signal",
					debugPreview(raw),
				)

				continue
			}

			nodeType, end, ok := parseStructuredCode(
				text,
				start,
				spec,
			)

			if !ok || end <= start {
				continue
			}

			log.Printf(
				"[AST CODE] language=%s node=%s bytes=%d-%d text=%q",
				spec.Name,
				nodeType,
				start,
				end,
				debugPreview(text[start:end]),
			)

			ranges = append(ranges, CodeRange{
				Start: start,
				End:   end,
				Type:  "CODE",
			})

			// Для Bash каждая строка анализируется отдельно.
			// Его AST уже ограничен одной строкой.
			if spec.Name != "Bash" {
				for i+1 < len(lines) &&
					lineStarts[i+1] < end {

					i++
				}
			}

			break
		}
	}

	return ranges
}

func matchesCodeAnchor(
	line string,
	anchors []*regexp.Regexp,
) bool {
	for _, anchor := range anchors {
		if anchor.MatchString(line) {
			return true
		}
	}

	return false
}

/*
isSyntaxCandidate

Первичный дешёвый фильтр.

Он НЕ должен решать, является ли строка кодом.
Его задача только не отдавать Tree-sitter каждую строку отчёта.

Поэтому здесь находятся очевидные generic-сигналы:
- assignment;
- control/declaration keywords;
- preprocessor;
- HTML opening tag.

Конкретные language anchors проверяются отдельно.
*/
func isSyntaxCandidate(line string) bool {
	if syntaxCandidateRegexp.MatchString(line) {
		return true
	}

	// CHANGED:
	// Generic regex не обязан знать синтаксис каждого языка.
	//
	// Например C#:
	//     public MyClass(...)
	//
	// Java:
	//     public void foo(...)
	//
	// HTML:
	//     <div>
	//
	// Поэтому после дешёвого generic-фильтра даём шанс
	// конкретным anchors.
	for _, spec := range codeLanguageSpecs {
		if matchesCodeAnchor(line, spec.Anchors) {
			return true
		}
	}

	return false
}

/*
hasCodeSignal

Дополнительный guard только для слабых Bash-команд.

Идея:
слово "test", "echo", "cat", "id" и т.п. само по себе
ничего не доказывает.

Но если рядом есть характерный shell-сигнал:

	$
	>
	|
	&&
	||
	;
	путь
	URL
	флаг
	assignment
	файл

то вероятность Bash-конструкции существенно выше.
*/
func hasCodeSignal(line string) bool {
	if line == "" {
		return false
	}

	// Shell variables / command substitution.
	if strings.Contains(line, "$") {
		return true
	}

	// Pipeline / command chaining.
	if strings.Contains(line, "|") ||
		strings.Contains(line, "&&") ||
		strings.Contains(line, "||") {
		return true
	}

	// Redirects.
	if strings.Contains(line, ">") ||
		strings.Contains(line, "<") {
		return true
	}

	// Command separator.
	if strings.Contains(line, ";") {
		return true
	}

	// Assignment.
	if regexp.MustCompile(
		`(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=`,
	).MatchString(line) {
		return true
	}

	// Options.
	if regexp.MustCompile(
		`(?:^|\s)--?[A-Za-z0-9]`,
	).MatchString(line) {
		return true
	}

	// URL.
	if strings.Contains(line, "://") {
		return true
	}

	// Paths.
	fields := strings.Fields(line)

	for _, field := range fields {
		if strings.HasPrefix(field, "./") ||
			strings.HasPrefix(field, "../") ||
			strings.HasPrefix(field, "/") {

			return true
		}

		if isFile(field) {
			return true
		}
	}

	return false
}

/*
parseStructuredCode

Главное отличие от старой архитектуры:

мы НЕ считаем скобки,
НЕ ищем ';',
НЕ решаем, сколько следующих строк принадлежат коду.

Parser получает текст начиная с подозрительной конструкции
и сам строит AST.

Если в отчёте есть отдельная строка "...",
мы воспринимаем её как явно указанный автором конец
неполного фрагмента.
*/

func parseStructuredCode(
	text string,
	start int,
	spec codeLanguageSpec,
) (string, int, bool) {

	sourceText := text[start:]

	if spec.Name == "Bash" {
		if lineEnd := strings.IndexByte(sourceText, '\n'); lineEnd >= 0 {
			sourceText = sourceText[:lineEnd]
		}
	}

	targetOffset := 0

	/*
		PHP grammar ожидает PHP-контекст.
		Если в отчёте дан голый PHP-код:

		public function foo() {
		    ...
		}

		добавляем искусственный <?php.
	*/
	if spec.Name == "PHP" &&
		!phpOpenTagAnchor.MatchString(strings.TrimSpace(sourceText)) {

		const phpPrefix = "<?php\n"

		sourceText = phpPrefix + sourceText
		targetOffset = len(phpPrefix)
	}

	source := []byte(sourceText)

	if len(source) == 0 {
		return "", 0, false
	}

	parser := gotreesitter.NewParser(spec.Language)

	tree, err := parser.Parse(source)

	if err != nil || tree == nil {
		return "", 0, false
	}

	defer tree.Release()

	root := tree.RootNode()

	if root == nil {
		return "", 0, false
	}

	if spec.Name == "Bash" {
		return parseBashCommand(
			text,
			start,
			source,
			root,
			spec.Language,
		)
	}

	node := findStrongNodeAtOffset(
		root,
		spec.Language,
		spec.NodeTypes,
		targetOffset,
	)

	if node == nil || node.HasError() {
		return "", 0, false
	}

	nodeEnd := int(node.EndByte())

	if nodeEnd <= targetOffset ||
		nodeEnd > len(source) {

		return "", 0, false
	}

	/*
		Node coordinates относятся к source,
		где для PHP может быть добавлен <?php\n.

		Возвращаем координату относительно
		исходного текста отчёта.
	*/
	end := start + (nodeEnd - targetOffset)

	return node.Type(spec.Language), end, true
}

func findStrongNodeAtOffset(
	root *gotreesitter.Node,
	language *gotreesitter.Language,
	allowed map[string]struct{},
	targetOffset int,
) *gotreesitter.Node {

	if root == nil {
		return nil
	}

	var find func(*gotreesitter.Node) *gotreesitter.Node

	find = func(node *gotreesitter.Node) *gotreesitter.Node {
		if node == nil {
			return nil
		}

		start := int(node.StartByte())
		end := int(node.EndByte())

		// Узел полностью находится до нужной позиции.
		if end <= targetOffset {
			return nil
		}

		// Узел начинается уже после нужной позиции.
		if start > targetOffset {
			return nil
		}

		nodeType := node.Type(language)

		if start == targetOffset {
			if _, ok := allowed[nodeType]; ok {
				return node
			}
		}

		for _, child := range node.Children() {
			found := find(child)

			if found != nil {
				return found
			}
		}

		return nil
	}

	return find(root)
}

func findHTMLRanges(text string) []CodeRange {
	var ranges []CodeRange

	matches := htmlCodeRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		ranges = append(ranges, CodeRange{
			Start: match[0],
			End:   match[1],
			Type:  "CODE",
		})
	}

	return ranges
}

func findPHPBlockRanges(text string) []CodeRange {
	var ranges []CodeRange

	matches := phpBlockRegexp.FindAllStringIndex(text, -1)

	for _, match := range matches {
		ranges = append(ranges, CodeRange{
			Start: match[0],
			End:   match[1],
			Type:  "CODE",
		})
	}

	return ranges
}

func parseBashCommand(
	text string,
	start int,
	source []byte,
	root *gotreesitter.Node,
	language *gotreesitter.Language,
) (string, int, bool) {

	if root == nil {
		return "", 0, false
	}

	var command *gotreesitter.Node

	var find func(*gotreesitter.Node)

	find = func(node *gotreesitter.Node) {
		if node == nil || command != nil {
			return
		}

		if node.Type(language) == "command" {
			command = node
			return
		}

		for _, child := range node.Children() {
			find(child)

			if command != nil {
				return
			}
		}
	}

	find(root)

	if command == nil || command.HasError() {
		return "", 0, false
	}

	startByte := int(command.StartByte())
	endByte := int(command.EndByte())

	if startByte < 0 ||
		endByte <= startByte ||
		endByte > len(source) {

		return "", 0, false
	}

	commandEnd := findBashCodeEnd(
		command,
		source,
		language,
	)

	if commandEnd <= 0 {
		return "", 0, false
	}

	commandText := string(source[startByte:commandEnd])

	log.Printf(
		"[BASH CODE RANGE] bytes=%d-%d text=%q",
		startByte,
		commandEnd,
		commandText,
	)

	return "command", start + commandEnd, true
}

func getBashCommandName(
	command *gotreesitter.Node,
	source []byte,
	language *gotreesitter.Language,
) string {
	if command == nil {
		return ""
	}

	for _, child := range command.Children() {
		if child.Type(language) == "command_name" {
			start := int(child.StartByte())
			end := int(child.EndByte())

			if start >= 0 && end > start && end <= len(source) {
				return string(source[start:end])
			}
		}
	}

	return ""
}

func isBashTechnicalWord(s string) bool {
	if s == "" {
		return false
	}

	// Опции: -X, -H, --verbose, --output=file
	if strings.HasPrefix(s, "-") {
		return true
	}

	// URL
	if strings.Contains(s, "://") {
		return true
	}

	// Переменная / присваивание
	if strings.Contains(s, "=") {
		return true
	}

	// Относительный или абсолютный путь
	if strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "/") {
		return true
	}

	// Файл с известным расширением
	if isFile(s) {
		return true
	}

	return false
}

func findBashCodeEnd(
	command *gotreesitter.Node,
	source []byte,
	language *gotreesitter.Language,
) int {
	if command == nil {
		return 0
	}

	children := command.Children()

	end := 0
	optionValue := false
	seenCommand := false

	for _, child := range children {
		nodeType := child.Type(language)

		start := int(child.StartByte())
		childEnd := int(child.EndByte())

		if start < 0 || childEnd <= start || childEnd > len(source) {
			continue
		}

		value := string(source[start:childEnd])

		switch nodeType {
		case "variable_assignment":
			end = childEnd

		case "command_name":
			end = childEnd
			seenCommand = true

		case "word":
			if !seenCommand {
				continue
			}

			if optionValue {
				end = childEnd
				optionValue = false
				continue
			}

			if strings.HasPrefix(value, "-") {
				end = childEnd
				optionValue = true
				continue
			}

			if isBashSubcommand(value) {
				end = childEnd
				continue
			}

			if isBashTechnicalWord(value) {
				end = childEnd
				continue
			}

			// Обычное слово после уже найденной команды:
			// считаем, что это потенциальное начало prose.
			if end > 0 {
				return end
			}

			end = childEnd
		}
	}

	return end
}

func isBashSubcommand(s string) bool {
	switch s {
	case
		"status",
		"clone",
		"pull",
		"push",
		"fetch",
		"checkout",
		"switch",
		"branch",
		"log",
		"diff",
		"add",
		"commit",
		"reset",
		"merge",
		"rebase",
		"restart",
		"start",
		"stop",
		"enable",
		"disable",
		"reload":
		return true
	}

	return false
}
