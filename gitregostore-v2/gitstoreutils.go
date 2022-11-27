package gitregostoreclone

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/go-gota/gota/dataframe"
	opapolicy "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"go.uber.org/zap"
)

type storeSetter func(*GitRegoStore, string) error

const (
	attackTracksJsonFileName          = "attack_tracks"
	attackTracksPathPrefix            = "attack-tracks"
	frameworksJsonFileName            = "frameworks"
	controlsJsonFileName              = "controls"
	rulesJsonFileName                 = "rules"
	frameworkControlRelationsFileName = "FWName_CID_CName"
	ControlRuleRelationsFileName      = "ControlID_RuleName"
	defaultConfigInputsFileName       = "default_config_inputs"
	systemPostureExceptionFileName    = "exceptions"

	controlIDRegex = `^(?:[a-z]+|[A-Z]+)(?:[\-][v]?(?:[0-9][\.]?)+)(?:[\-]?[0-9][\.]?)+$`
)

var controlIDRegexCompiled *regexp.Regexp = nil

var storeSetterMapping = map[string]storeSetter{
	attackTracksJsonFileName:          (*GitRegoStore).setAttackTracks,
	frameworksJsonFileName:            (*GitRegoStore).setFrameworks,
	controlsJsonFileName:              (*GitRegoStore).setControls,
	rulesJsonFileName:                 (*GitRegoStore).setRules,
	frameworkControlRelationsFileName: (*GitRegoStore).setFrameworkControlRelations,
	ControlRuleRelationsFileName:      (*GitRegoStore).setControlRuleRelations,
	defaultConfigInputsFileName:       (*GitRegoStore).setDefaultConfigInputs,
	systemPostureExceptionFileName:    (*GitRegoStore).setSystemPostureExceptionPolicies,
}

type InnerTree []struct {
	PATH string `json:"path"`
}
type Tree struct {
	TREE InnerTree `json:"tree"`
}

// func setURL()
func (gs *GitRegoStore) setURL() {
	var url string

	if isUrlRelease(gs.Path) {
		url = gs.BaseUrl + "/" + gs.Owner + "/" + gs.Repository + "/" + gs.Path + "/" + gs.Tag
	} else {
		url = gs.BaseUrl + "/" + gs.Owner + "/" + gs.Repository + "/" + gs.Path + "/" + gs.Branch + "?recursive=1"
	}
	gs.URL = url
}

func (gs *GitRegoStore) setObjects() error {
	var err error
	if isUrlRelease(gs.URL) {
		err = gs.setObjectsFromReleaseLoop()
	} else {
		err = gs.setObjectsFromRepoLoop()
	}
	return err
}

func isUrlRelease(u string) bool {
	return strings.Contains(u, "releases")
}

// ========================== set Objects From Repo =====================================

func (gs *GitRegoStore) setObjectsFromRepoLoop() error {
	var wg sync.WaitGroup
	wg.Add(1)
	var e error

	go func() {
		f := true
		for {
			if err := gs.setObjectsFromRepoOnce(); err != nil {
				e = err
			}
			if f {
				wg.Done() // first update to done
				f = false
			}
			if !gs.Watch {
				return
			}
			time.Sleep(time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute)
		}
	}()
	wg.Wait()
	return e
}

func (gs *GitRegoStore) clone() error {
	if gs.cloneDir != "" {
		return nil
	}
	tmpDir, err := os.MkdirTemp("", "gitregostore-regolibrary")
	if err != nil {
		return err
	}
	cloneDir := filepath.Join(tmpDir, gs.Repository)
	cloneOpts := git.CloneOptions{
		URL:           fmt.Sprintf("https://github.com/%s/%s.git", gs.Owner, gs.Repository),
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(gs.Branch),
		SingleBranch:  true,
		Depth:         1, // get only the latest commits
	}
	_, err = git.PlainClone(cloneDir, false, &cloneOpts)
	if err == nil {
		gs.cloneDir = cloneDir
	}
	return err
}

// Close cleans up the temporary files if there are
func (gs *GitRegoStore) Close() {
	if gs.cloneDir != "" {
		os.RemoveAll(filepath.Base(gs.cloneDir))
	}
}

func (gs *GitRegoStore) syncClone() error {
	if gs.cloneDir == "" {
		return gs.clone()
	}
	pullOpts := git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(gs.Branch),
		// SingleBranch:  true,
		// Depth: 1, // get only the latest commits
	}
	r, err := git.PlainOpen(gs.cloneDir)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&pullOpts)
	return err
}

func (gs *GitRegoStore) setRulesFromLocalRepo() error {
	dir := filepath.Join(gs.cloneDir, rulesJsonFileName)
	rulesDirs, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, rulesDir := range rulesDirs {
		if !rulesDir.IsDir() {
			continue
		}
		err = gs.setRuleFromLocalRepo(filepath.Join(dir, rulesDir.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *GitRegoStore) setRuleFromLocalRepo(path string) error {
	// metadata
	metadata, err := os.ReadFile(filepath.Join(path, "rule.metadata.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	rule := &opapolicy.PolicyRule{}
	err = JSONDecoder(string(metadata)).Decode(rule)
	if err != nil {
		return err
	}

	// raw
	raw, err := os.ReadFile(filepath.Join(path, "raw.rego"))
	if err != nil {
		return err
	}
	rule.Rule = string(raw)

	// filter
	filter, err := os.ReadFile(filepath.Join(path, "filter.rego"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rule.ResourceEnumerator = string(filter)

	gs.Rules = append(gs.Rules, *rule)
	return nil
}

func (gs *GitRegoStore) setControlsFromLocalRepo() error {
	dir := filepath.Join(gs.cloneDir, controlsJsonFileName)
	return gs.setGenericObjectsFromLocalRepo(dir, gs.setControl)
}

func (gs *GitRegoStore) setFrameworksFromLocalRepo() error {
	dir := filepath.Join(gs.cloneDir, frameworksJsonFileName)
	return gs.setGenericObjectsFromLocalRepo(dir, gs.setFramework)
}
func (gs *GitRegoStore) setAttackTracksFromLocalRepo() error {
	dir := filepath.Join(gs.cloneDir, attackTracksPathPrefix)
	return gs.setGenericObjectsFromLocalRepo(dir, gs.setAttackTrack)
}
func (gs *GitRegoStore) setSystemExceptionsFromLocalRepo() error {
	dir := filepath.Join(gs.cloneDir, systemPostureExceptionFileName)
	return gs.setGenericObjectsFromLocalRepo(dir, gs.setSystemPostureExceptionPolicy)
}

func (gs *GitRegoStore) setDefaultConfigInputsFromLocalRepo() error {
	defaultConfigInputs, err := os.ReadFile(filepath.Join(gs.cloneDir, "default-config-inputs.json"))
	if err != nil {
		return err
	}
	return gs.setDefaultConfigInputs(string(defaultConfigInputs))
}

func (gs *GitRegoStore) setControlRuleRelationsFromLocalRepo() error {
	controlRuleRelations, err := os.ReadFile(filepath.Join(gs.cloneDir, "ControlID_RuleName.csv"))
	if err != nil {
		return err
	}
	return gs.setControlRuleRelations(string(controlRuleRelations))
}

func (gs *GitRegoStore) setFrameworkControlRelationsFromRepo() error {
	controlRuleRelations, err := os.ReadFile(filepath.Join(gs.cloneDir, "FWName_CID_CName.csv"))
	if err != nil {
		return err
	}
	return gs.setControlRuleRelations(string(controlRuleRelations))
}

// setGenericObjectsFromLocalRepo set simple json objects from given directory `path` to `gs` using `setFunc`
func (gs *GitRegoStore) setGenericObjectsFromLocalRepo(path string, setFunc func(string) error) error {
	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		path := filepath.Join(path, file.Name())
		if file.IsDir() || !strings.HasSuffix(path, ".json") {
			continue
		}
		attackTrack, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		err = setFunc(string(attackTrack))
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *GitRegoStore) setObjectsFromRepoOnce() error {
	// clone / pull repo
	err := gs.syncClone()
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil
		}
		return err
	}

	//use a clone of the store for the update to avoid long lock time
	gsClone := newGitRegoStore(gs.BaseUrl, gs.Owner, gs.Repository, gs.Path, gs.Tag, gs.Branch, gs.FrequencyPullFromGitMinutes)
	gsClone.cloneDir = gs.cloneDir

	// Set all the rego library objects
	for objType, setFunc := range map[string]func() error{
		"Rules":                     gsClone.setRulesFromLocalRepo,
		"Controls":                  gsClone.setControlsFromLocalRepo,
		"Frameworks":                gsClone.setFrameworksFromLocalRepo,
		"AttackTracks":              gsClone.setAttackTracksFromLocalRepo,
		"SystemExceptions":          gsClone.setSystemExceptionsFromLocalRepo,
		"DefaultConfigInputs":       gsClone.setDefaultConfigInputsFromLocalRepo,
		"ControlRuleRelations":      gsClone.setControlRuleRelationsFromLocalRepo,
		"FrameworkControlRelations": gsClone.setFrameworkControlRelationsFromRepo,
	} {
		err = setFunc()
		if err != nil {
			return fmt.Errorf("setObjectsFromRepoOnce: failed to set %s: %w", objType, err)
		}
	}

	gs.copyData(gsClone)
	return nil
}

func (gs *GitRegoStore) setFramework(respStr string) error {
	framework := &opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(framework); err != nil {
		return err
	}
	gs.Frameworks = append(gs.Frameworks, *framework)
	return nil
}

func (gs *GitRegoStore) setAttackTrack(respStr string) error {
	attackTrack := &v1alpha1.AttackTrack{}
	if err := JSONDecoder(respStr).Decode(attackTrack); err != nil {
		return err
	}
	gs.AttackTracks = append(gs.AttackTracks, *attackTrack)
	return nil
}

func (gs *GitRegoStore) setSystemPostureExceptionPolicy(respStr string) error {
	exceptions := []armotypes.PostureExceptionPolicy{}
	if err := JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return err
	}

	gs.SystemPostureExceptionPolicies = append(gs.SystemPostureExceptionPolicies, exceptions...)
	return nil
}

func (gs *GitRegoStore) setControl(respStr string) error {
	control := &opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(control); err != nil {
		return err
	}
	gs.Controls = append(gs.Controls, *control)
	return nil
}

func (gs *GitRegoStore) setRulesWithRawRego(respStr string, path string) error {
	rule := &opapolicy.PolicyRule{}
	rawRego, err := gs.getRulesWithRawRego(rule, respStr, path)
	if err != nil {
		return err
	}
	filterRego, err := gs.getRulesWithFilterRego(rule, respStr, path)
	if err != nil && !strings.Contains(err.Error(), "404 Not Found") {
		return err
	}
	rule.Rule = rawRego
	rule.ResourceEnumerator = filterRego
	gs.Rules = append(gs.Rules, *rule)
	return nil
}

func (gs *GitRegoStore) getRulesWithRawRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/raw.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

func (gs *GitRegoStore) getRulesWithFilterRego(rule *opapolicy.PolicyRule, respStr string, path string) (string, error) {
	if err := JSONDecoder(respStr).Decode(rule); err != nil {
		return "", err
	}
	rawRegoPath := path[:strings.LastIndex(path, "/")] + "/filter.rego"
	respString, err := HttpGetter(gs.httpClient, rawRegoPath)
	if err != nil {
		return "", err
	}
	return respString, nil
}

// ======================== set Objects From Release =============================================

func (gs *GitRegoStore) setObjectsFromReleaseLoop() error {
	var wg sync.WaitGroup
	wg.Add(1)
	var e error
	go func() {
		f := true
		for {
			if err := gs.setObjectsFromReleaseOnce(); err != nil {
				e = err
			}
			if f {
				wg.Done() // first update to done
				f = false
			}
			if !gs.Watch {
				return
			}
			time.Sleep(time.Duration(gs.FrequencyPullFromGitMinutes) * time.Minute)
		}
	}()
	wg.Wait()
	return e
}

func (gs *GitRegoStore) setObjectsFromReleaseOnce() error {

	for kind, storeSetterMappingFunc := range storeSetterMapping {
		respStr, err := HttpGetter(gs.httpClient, fmt.Sprintf("%s/%s", gs.URL, kind))
		if err != nil {
			return fmt.Errorf("error getting: %s from: '%s' ,error: %s", kind, gs.URL, err)
		}
		if err = storeSetterMappingFunc(gs, respStr); err != nil {
			return err
		}
	}
	return nil
}

func (gs *GitRegoStore) setFrameworks(respStr string) error {
	frameworks := []opapolicy.Framework{}
	if err := JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return err
	}
	gs.frameworksLock.Lock()
	defer gs.frameworksLock.Unlock()
	gs.Frameworks = frameworks
	return nil
}

func (gs *GitRegoStore) setAttackTracks(respStr string) error {
	attacktracks := []v1alpha1.AttackTrack{}
	if err := JSONDecoder(respStr).Decode(&attacktracks); err != nil {
		return err
	}
	gs.attackTracksLock.Lock()
	defer gs.attackTracksLock.Unlock()
	gs.AttackTracks = attacktracks
	return nil
}

func (gs *GitRegoStore) setControls(respStr string) error {
	controls := []opapolicy.Control{}
	if err := JSONDecoder(respStr).Decode(&controls); err != nil {
		return err
	}
	gs.controlsLock.Lock()
	defer gs.controlsLock.Unlock()
	gs.Controls = controls
	return nil
}

func (gs *GitRegoStore) setRules(respStr string) error {
	rules := &[]opapolicy.PolicyRule{}
	if err := JSONDecoder(respStr).Decode(rules); err != nil {
		return err
	}
	gs.rulesLock.Lock()
	defer gs.rulesLock.Unlock()
	gs.Rules = *rules
	return nil
}
func (gs *GitRegoStore) setDefaultConfigInputs(respStr string) error {
	defaultConfigInputs := armotypes.CustomerConfig{}
	if err := JSONDecoder(respStr).Decode(&defaultConfigInputs); err != nil {
		return err
	}
	gs.DefaultConfigInputsLock.Lock()
	defer gs.DefaultConfigInputsLock.Unlock()
	gs.DefaultConfigInputs = defaultConfigInputs
	return nil
}

func (gs *GitRegoStore) setSystemPostureExceptionPolicies(respStr string) error {
	exceptions := []armotypes.PostureExceptionPolicy{}
	if err := JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return err
	}
	gs.systemPostureExceptionPoliciesLock.Lock()
	defer gs.systemPostureExceptionPoliciesLock.Unlock()

	gs.SystemPostureExceptionPolicies = append(gs.SystemPostureExceptionPolicies, exceptions...)
	return nil
}

func (gs *GitRegoStore) setFrameworkControlRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))
	gs.FrameworkControlRelations = df
	return nil
}

func (gs *GitRegoStore) setControlRuleRelations(respStr string) error {
	df := dataframe.ReadCSV(strings.NewReader(respStr))
	gs.ControlRuleRelations = df
	return nil
}

func (gs *GitRegoStore) lockAll() {
	gs.frameworksLock.Lock()
	gs.controlsLock.Lock()
	gs.rulesLock.Lock()
	gs.attackTracksLock.Lock()
	gs.systemPostureExceptionPoliciesLock.Lock()
	gs.DefaultConfigInputsLock.Lock()
}

func (gs *GitRegoStore) rLockAll() {
	gs.frameworksLock.RLock()
	gs.controlsLock.RLock()
	gs.rulesLock.RLock()
	gs.attackTracksLock.RLock()
	gs.systemPostureExceptionPoliciesLock.RLock()
	gs.DefaultConfigInputsLock.RLock()
}

func (gs *GitRegoStore) unlockAll() {
	gs.frameworksLock.Unlock()
	gs.controlsLock.Unlock()
	gs.rulesLock.Unlock()
	gs.attackTracksLock.Unlock()
	gs.systemPostureExceptionPoliciesLock.Unlock()
	gs.DefaultConfigInputsLock.Unlock()
}

func (gs *GitRegoStore) rUnlockAll() {
	gs.frameworksLock.RUnlock()
	gs.controlsLock.RUnlock()
	gs.rulesLock.RUnlock()
	gs.attackTracksLock.RUnlock()
	gs.systemPostureExceptionPoliciesLock.RUnlock()
	gs.DefaultConfigInputsLock.RUnlock()
}

func (gs *GitRegoStore) copyData(other *GitRegoStore) {
	other.rLockAll()
	defer other.rUnlockAll()
	gs.lockAll()
	defer gs.unlockAll()
	gs.Frameworks = other.Frameworks
	gs.Controls = other.Controls
	gs.Rules = other.Rules
	gs.AttackTracks = other.AttackTracks
	gs.SystemPostureExceptionPolicies = other.SystemPostureExceptionPolicies
	gs.DefaultConfigInputs = other.DefaultConfigInputs
	gs.ControlRuleRelations = other.ControlRuleRelations
	gs.FrameworkControlRelations = other.FrameworkControlRelations
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *json.Decoder {
	dec := json.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}

func HttpGetter(httpClient *http.Client, fullURL string) (string, error) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	respStr, err := HTTPRespToString(resp)
	if err != nil {
		return "", err
	}
	return respStr, nil
}

// HTTPRespToString parses the body as string and checks the HTTP status code, it closes the body reader at the end
// TODO: FIX BUG: status code is not being checked when the body is empty
func HTTPRespToString(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	strBuilder := strings.Builder{}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		strBuilder.Grow(int(resp.ContentLength))
	}
	bytesNum, err := io.Copy(&strBuilder, resp.Body)
	respStr := strBuilder.String()
	if err != nil {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		return "", fmt.Errorf("HTTP request failed. URL: '%s', Read-ERROR: '%s', HTTP-CODE: '%s', BODY(top): '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), err, resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respStrNewLen := len(respStr)
		if respStrNewLen > 1024 {
			respStrNewLen = 1024
		}
		err = fmt.Errorf("HTTP request failed. URL: '%s', HTTP-ERROR: '%s', BODY: '%s', HTTP-HEADERS: %v, HTTP-BODY-BUFFER-LENGTH: %v", resp.Request.URL.RequestURI(), resp.Status, respStr[:respStrNewLen], resp.Header, bytesNum)
	}
	zap.L().Debug("In HTTPRespToString - request end succesfully",
		zap.String("URL", resp.Request.URL.String()), zap.Int("contentLength", int(resp.ContentLength)))

	return respStr, err
}

func isControlID(c string) bool {

	// Compile regex only once
	if controlIDRegexCompiled == nil {
		compiled, err := regexp.Compile(controlIDRegex)
		if err != nil {
			return false
		}
		controlIDRegexCompiled = compiled
	}

	// Match
	return controlIDRegexCompiled.MatchString(c)
}
