package app

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

// ResultScan is the final scan result.
type ResultScan struct {
	Matches []Match
	RepoSearchResult
}

// Match represents a keyword/API key match
type Match struct {
	Text        string
	KeywordType string
	Line        Line
	Commit      string
	CommitFile  string
	File        string
}

// Line represents a text line, the context for a Match.
type Line struct {
	Text          string
	MatchIndex    int
	MatchEndIndex int
}

var scannedRepos = make(map[string]bool)
var apiKeyMap = make(map[string]bool)

var customRegexes []*regexp.Regexp
var loadedRegexes = false

// ScanAndPrintResult scans and prints information about a search result.
func ScanAndPrintResult(client *http.Client, repo RepoSearchResult) {
	if scannedRepos[repo.Repo] {
		return
	}
	base := GetRawURLForSearchResult(repo)
	data, err := DownloadRawFile(client, base, repo)
	if err != nil {
		log.Fatal(err)
	}
	resultString := string(data)

	matches, score := GetMatchesForString(resultString, repo)
	if repo.Source == "repo" && (GetFlags().DigCommits || GetFlags().DigRepo) && RepoIsUnpopular(client, repo) && score > -1 {
		scannedRepos[repo.Repo] = true
		for _, match := range Dig(repo) {
			matches = append(matches, match)
		}
	}

	if len(matches) > 0 {
		if !GetFlags().ResultsOnly {
			resultRepoURL := GetRepoURLForSearchResult(repo)
			color.Green("[" + resultRepoURL + "]")
		}
		for _, result := range matches {
			if result.KeywordType == "apiKey" {
				if apiKeyMap[result.Text] == true {
					continue
				}
				apiKeyMap[result.Text] = true
			}
			if GetFlags().ResultsOnly {
				fmt.Println(result.Text)
			} else {
				PrintContextLine(result.Line)
				PrintResultLink(repo, result)
			}
		}
	}
}

// MatchKeywords takes a string and checks if it contains sensitive information using pattern matching.
func MatchKeywords(source string) (matches []Match) {
	if GetFlags().NoKeywords || source == "" {
		return matches
	}
	base64Regex := "\\b[a-zA-Z0-9/+]*={0,2}\\b"
	regex := regexp.MustCompile(base64Regex)

	base64Strings := regex.FindAllString(source, -1)
	if base64Strings != nil {
		for _, match := range base64Strings {
			decoded, _ := b64.StdEncoding.DecodeString(match)
			decodedMatches := MatchKeywords(string(decoded))

			for _, decodedMatch := range decodedMatches {
				matches = append(matches, decodedMatch)
			}
		}
	}

	regexString := "(?i)(SF_USERNAME|AKIA" +
		"|db_username|db_password|socks5:" +
		"|hooks.slack.com|pt_token|full_resolution_time_in_minutes" +
		"|xox[a-zA-Z]-[a-zA-Z0-9-]+" +
		"|s3\\.console\\.aws\\.amazon\\.com" +
		"|JEKYLL_GITHUB_TOKEN|codecov_token|connectionstring|consumer_key|github_token|irc_pass|NODE_ENV|npmrc _auth" +
		"|x-api-key|HEROKU_API_KEY)" //|[\\w\\.=-]+@" + regexp.QuoteMeta(result.Query) + ")\\b"
	regex = regexp.MustCompile(regexString)
	matchStrings := regex.FindAllString(source, -1)
	for _, match := range matchStrings {

		if containsVariablepassword(match) {
				continue
		}

		if LineContainsCommon(source) {
				continue
		}

		matches = append(matches, Match{
			KeywordType: "keyword",
			Text:        string(match),
			Line:        GetLine(source, match),
		})
	}
	return matches
}

// MatchAPIKeys takes a string and checks if it contains API keys using pattern matching and entropy checking.
func MatchAPIKeys(source string) (matches []Match) {
	if GetFlags().NoAPIKeys || source == "" {
		return matches
	}

	base64Regex := "\\b[a-zA-Z0-9/+]*={0,2}\\b"
	regex := regexp.MustCompile(base64Regex)
	base64Strings := regex.FindAllString(source, -1)
	if base64Strings != nil {
		for _, match := range base64Strings {
			decoded, _ := b64.StdEncoding.DecodeString(match)
			decodedMatches := MatchAPIKeys(string(decoded))

			for _, decodedMatch := range decodedMatches {
				matches = append(matches, decodedMatch)
			}
		}
	}

	regexString := "(?i)(ACCESS|SECRET|LICENSE|CRYPT|PASS|API|ADMIN|TOKEN|PWD|UID|Authorization|Bearer|database|db|username|host|gitlab)[\\w\\s:=\"']{0,10}[=:\\s'\"]([\\w\\-+=\"']{5,})"
	regex = regexp.MustCompile(regexString)
	matchStrings := regex.FindAllStringSubmatch(source, -1)
	for _, match := range matchStrings {
		if Entropy(match[2]) > 3.5 {
			if containsSequence(match[2]) {
				continue
			}

			if containsCommonWord(match[2]) {
				continue
			}

			if containsVariablepassword(match[2]) {
				continue
			}
			
			if LineContainsCommon(source) {
				continue
			}

			matches = append(matches, Match{
				KeywordType: "apiKey",
				Text:        string(match[2]),
				Line:        GetLine(source, match[2]),
			})
		}
	}
	return matches
}

// MatchCustomRegex matches a string against a slice of regexes.
func MatchCustomRegex(source string) (matches []Match) {
	if source == "" {
		return matches
	}
	base64Regex := "\\b[a-zA-Z0-9/+]*={0,2}\\b"
	regex := regexp.MustCompile(base64Regex)
	base64Strings := regex.FindAllString(source, -1)
	if base64Strings != nil {
		for _, match := range base64Strings {
			decoded, _ := b64.StdEncoding.DecodeString(match)
			decodedMatches := MatchCustomRegex(string(decoded))

			for _, decodedMatch := range decodedMatches {
				matches = append(matches, decodedMatch)
			}
		}
	}
	for _, regex := range customRegexes {
		regMatches := regex.FindAllString(source, -1)
		for _, regMatch := range regMatches {
			matches = append(matches, Match{
				KeywordType: "custom",
				Text:        regMatch,
				Line:        GetLine(source, regMatch),
			})
		}

	}
	return matches
}

// MatchFileExtensions matches interesting file extensions.
func MatchFileExtensions(source string, result RepoSearchResult) (matches []Match) {
	if GetFlags().NoFiles || source == "" {
		return matches
	}
	regexString := "(?i)(credentials|deployment-config\\.json|filezilla\\.xml|id_rsa|pgpass|vpn|\\.vpn|\\.ovpn|pg_pass|secrets\\.yml|vim_settings\\.xml|mysql_history|terraform\\.tfvars|database\\.yml|secret_token\\.rb|connections\\.xml|(\\.(zip|dockercfg|cshrc|ftpconfig|pgpass|remote-sync\\.json|s3cfg|git-credentials|env|conf|htpasswd|log|exports|ovpn|cscfg|rdp|mdf|sdf|jks|tblk)))$"
	regex := regexp.MustCompile(regexString)
	// fmt.Println(source)
	matchStrings := regex.FindAllStringSubmatch(source, -1)
	for _, match := range matchStrings {
		if len(match) > 0 {
			matches = append(matches, Match{
				KeywordType: "fileExtension",
				Text:        string(match[0]),
				Line:        GetLine(source, match[0]),
			})
		}
	}
	return matches
}

// GetLine grabs the full line of the first instance of a pattern within it
func GetLine(source string, pattern string) Line {
	patternIndex := strings.Index(source, pattern)
	i, j := 0, len(pattern)
	for patternIndex+i > 0 && i > -30 && source[patternIndex+i] != '\n' && source[patternIndex+i] != '\r' {
		i--
	}
	for patternIndex+j < len(source) && j < 10 && source[patternIndex+j] != '\n' && source[patternIndex+j] != '\r' {
		j++
	}
	return Line{Text: source[patternIndex+i : patternIndex+j], MatchIndex: Abs(i), MatchEndIndex: j + Abs(i)}
}

// PrintContextLine pretty-prints the line of a Match, with the result highlighted.
func PrintContextLine(line Line) {
	red := color.New(color.FgRed).SprintFunc()
	fmt.Printf("%s%s%s\n",
		line.Text[:line.MatchIndex],
		red(line.Text[line.MatchIndex:line.MatchEndIndex]),
		line.Text[line.MatchEndIndex:])
}

// Entropy calculates the Shannon entropy of a string
func Entropy(str string) (entropy float32) {
	if str == "" {
		return entropy
	}
	freq := 1.0 / float32(len(str))
	freqMap := make(map[rune]float32)
	for _, char := range str {
		freqMap[char] += freq
	}
	for _, entry := range freqMap {
		entropy -= entry * float32(math.Log2(float64(entry)))
	}
	return entropy
}

// PrintResultLink prints a link to the result.
func PrintResultLink(result RepoSearchResult, match Match) {
	if match.Commit != "" {
		color.New(color.Faint).Println("https://github.com/" + result.Repo + "/commit/" + match.Commit)
	} else {
		file := match.File
		if file == "" {
			file = result.File
		}
		color.New(color.Faint).Println(result.URL)
	}
}

func initializeCustomRegexes() {
	loadedRegexes = true
	regexStrings := GetFileLines(GetFlags().RegexFile)
	for _, regexString := range regexStrings {
		regex, err := regexp.Compile(regexString)
		if err != nil {
			color.Red("[!] Invalid regex: `" + regexString + " ` .")
			break
		}
		customRegexes = append(customRegexes, regex)
	}
}

// GetMatchesForString runs pattern matching and scoring checks on the given string
// and returns the matches.
func GetMatchesForString(source string, result RepoSearchResult) (matches []Match, score int) {
	if !GetFlags().NoKeywords {
		for _, match := range MatchKeywords(source) {
			matches = append(matches, match)
			score += 2
		}
	}
	if !GetFlags().NoAPIKeys {
		for _, match := range MatchAPIKeys(source) {
			matches = append(matches, match)
			score += 2
		}
	}
	if GetFlags().RegexFile != "" {
		if !loadedRegexes {
			initializeCustomRegexes()
		}
		for _, match := range MatchCustomRegex(source) {
			matches = append(matches, match)
			score += 4
		}
	}
	if !GetFlags().NoScoring {
		matched, err := regexp.MatchString("(?i)(phishing|defenceblocklist|block|list|rumors|h1domains|bugbounty|bug-bounty|bounty-targets|url_short|url_list|alexa|twitter|blacklists|blacklist)", result.Repo+result.File)
		CheckErr(err)
		if matched {
			score -= 5
		}
		matched, err = regexp.MatchString("(?i)(\\.md|\\.csv)$", result.File)
		CheckErr(err)
		if matched {
			score -= 2
		}
		matched, err = regexp.MatchString("^vim_settings\\.xml$", result.File)
		CheckErr(err)
		if matched {
			score += 5
		}
		if len(matches) > 0 {
			matched, err = regexp.MatchString("(?i)\\.(json|yml|py|rb|java|go|php|xml|env|js)$", result.File)
			CheckErr(err)
			if matched {
				score++
			}
			matched, err = regexp.MatchString("(?i)\\.(htpasswd|ftpconfig|mysql_history)$", result.File)
			CheckErr(err)
			if matched {
				score += 3
			}
		}
		regex := regexp.MustCompile("(alexa|urls|adblock|domain|dns|top1000|top-1000|httparchive" +
			"|blacklist|hosts|blacklists|rumor|ads|whitelist|crunchbase|tweets|tld|hosts\\.txt" +
			"|host\\.txt|aquatone|recon-ng|hackerone|bugcrowd|xtreme|timestamp_secret|list|tracking|malicious|ipv(4|6)|host\\.txt)")
		fileNameMatches := regex.FindAllString(result.File, -1)
		CheckErr(err)
		if len(fileNameMatches) > 0 {
			score -= int(math.Pow(2, float64(len(fileNameMatches))))
		}
		if score <= 0 && !GetFlags().NoScoring {
			matches = nil
		}
	}
	if GetFlags().NoScoring {
		score = 10
	}
	return matches, score
}

// Additional filters based off of https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf

var r *regexp.Regexp

func containsCommonWord(str string) bool {
	if r == nil {
		r = regexp.MustCompile("(?i)(" + strings.Join(getProgrammingWords(), "|") + ")")
	}
	if r.FindString(str) != "" {
		return true
	}
	return false
}

func containsSequence(str string) bool {
	b := []byte(str)
	matches := 0
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] || b[i] == b[i-1]-1 || b[i] == b[i-1]+1 {
			matches++
		}
	}
	// fmt.Println(float64(matches) / float64(len(b)))
	// over half of the characters in the string were a sequence
	return float64(matches)/float64(len(b)) > 0.5
}

var rag *regexp.Regexp

func containsVariablepassword(str string) bool {
	if rag == nil {
		rag = regexp.MustCompile("(?i)((env\\.)|(config\\.)|(secrets\\.)|(timestamp_secret)|(refresh_token)|(__cfduid)|(slovakia)|(coinmarketcap)|(uuid))")
	}
	if rag.FindString(str) != "" {
		return true
	}
	return false
}

// Checks URL for defined words
var reg *regexp.Regexp
func LineContainsCommon(source string) bool {
	if reg == nil {
		reg = regexp.MustCompile("(?i)(rumors|twitter|blacklist|ICO|package|lykke)")
	}
	if reg.FindString(source) != "" {
		return true
	}
	return false
}
