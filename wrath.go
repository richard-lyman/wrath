/*

Wrath - redis-backed auth - rauth - wrath

Base Entities

There are: Identities, Actors, Roles, and Relationships.

An Identity is referred to through a UUID and is a
	pair of [id, password], where the id and password are JSON strings - There is a root identity - An Identities id MUST BE GLOBALLY UNIQUE.
An Actor is referred to through a UUID and is a
	JSON object - There is a root actor.
A Role is referred to through a UUID and is a
	JSON string - There is a root role - A Role MUST BE GLOBALLY UNIQUE.
A Relationship  is referred to through a UUID, with the following as possible relationships:
	An Identity     can have zero or *one* Actor(s) - the root identity is associated with the root actor
	An Actor        can have zero or more Identities
	An Actor        can have zero or more Roles
	A Role          can have zero or more Actors - the root actor is associated with the root role

Terms

Token:
	the temporary proof of having provided a valid Identity
Authentication:
	the process of an Actor providing an Identity and recieving a Token
Authorization:
	the verification that a Token is related to a Role

Authorization Highlights

Nothing can be done without a valid Token.
The root role represents authorization to do anything in the system - except delete the root identity, root actor, root role, or the relation of root identity to root actor, or the relation of root actor to root role.
No other Role represents the authorization for any action in the system.

The root role is a Role who's value is the JSON string `"root"`.
A Token is a UUID whos value is a tuuid (see the '/t' definition below).
Without a token, a 401 is returned for all calls.
Without a valid token representing the authorization of the root role, a 403 is returned.

Redis Key Types

        UNIQUE:IDENTITY         set of Identity ids
        UNIQUE:ROLE             set of Role values

        IDENTITY:uuid           string
        ACTOR:uuid              string
        ROLE:uuid               string

        IDENTITY:LIST           set of 'iuuids'
        ACTOR:LIST              set of 'auuids'
        ROLE:LIST               set of 'ruuids'

        ACTOR:IDENTITY:auuid    set of 'iuuids'
        IDENTITY:ACTOR:iuuid    string of auuid

        ACTOR:ROLE:auuid        set of 'ruuids'
        ROLE:ACTOR:ruuid        set of 'auuids'

Routes

/i
	POST /i (create an Identity - body is json array - first value is anything (a uuid or email are common) and it is required to be unique - second value is password - response is uuid - 201 or 400)
	GET /i (get all identities - response is object of uuids to json arrays - 200)
	GET /i/{uuid} (get uuid or email associated with the specific Identity - 200 or 404)
	PUT /i/{uuid} (set json array associated with the specific Identity - 200 or 400 or 404)
	DELETE /i/{uuid} (200 or 404)
/a
	POST /a (create an Actor - body is json object - response is uuid - 201 or 400)
	GET /a (get all Actors - response is object of uuids to json objects - 200)
	GET /a/{uuid} (get json object associated with the specific Actor - 200 or 404)
	PUT /a/{uuid} (set json object associated with the specific Actor - 200 or 400 or 404)
	DELETE /a/{uuid} (200 or 404)
/r
	POST /r (create a Role - body is json string and is required to be unique - response is uuid - 201 or 400)
	GET /r (get all Roles - response is object of uuids to strings - 200)
	GET /r/{uuid} (get json string associated with the specific Role - 200 or 404)
	PUT /r/{uuid} (set json string associated with the specific Role - 200 or 400 or 404)
	DELETE /r/{uuid} (200 or 404)
/ai
	POST /ai/{auuid}/{iuuid} (associate an Actor with an Identity - 201 or 400)
	GET /ai (get all associations of Actors with identities - response is object of auuid to array of iuuids - 200)
	GET /ai/{uuid} (get json array of associated uuids - 200 or 404)
	DELETE /ai/{auuid}/{iuuid} (200 or 404)
/ar
	POST /ar/{auuid}/{ruuid} (associate an Actor with a Role - 201 or 400)
	GET /ar (get all associations of Actors with Roles - response is object of auuid to array of ruuids - 200)
	GET /ar/{uuid} (get json array of associated uuids - 200 or 404)
	DELETE /ar/{auuid}/{ruuid} (200 or 404)
/z
	GET /z/{url encoded uuid or email} (response is array of Roles associated with Identity - 200 or 404)
/t
	GET /t (authorization header has "BASIC " prefixed b64 of colon joined Identity pair - response is tuuid - 200 or 404)

*/
package main

/*
The MIT License (MIT)

Copyright (c) 2015 Richard Lyman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/richard-lyman/redisb"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
)

var c net.Conn

func genUUID() string {
	b := make([]byte, 16)
	c, err := io.ReadFull(rand.Reader, b)
	if c != 16 || err != nil {
		panic(fmt.Sprintf("Not able to generate a UUID: %q", err))
	}
	b[8] = (b[8] & 0x3F) | 0x80
	b[6] = b[6] & 0x4F
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

const NON_UNIQUE_IDENTITY = "The provided identity is not unique, or we're unable to verify it's uniqueness."
const NON_UNIQUE_ROLE = "The provided role is not unique, or we're unable to verify it's uniqueness."

var hostPort = flag.String("hostPort", ":8765", "The host:port to bind to. To bind to all interfaces, provide ':port' as the value.")
var redisHostPort = flag.String("redisHostPort", "localhost:6379", "The host:port for redis.")
var tokenTTL = flag.String("tokenTTL", "3600", "The TTL for TOKEN keys in Redis.")
var certFile = flag.String("certFile", "", "Location of certFile - if this flag and the keyFile flag are given values, HTTPS will be used.")
var keyFile = flag.String("keyFile", "", "Location of keyFile - if this flag and the certFile flag are given values, HTTPS will be used.")

func main() {
	flag.Parse()
	tmp, err := net.Dial("tcp", *redisHostPort)
	if err != nil {
		log.Fatalf("Unable to connect to redis: %s", err)
	}
	c = tmp
	ensureRoot()
	router := mux.NewRouter()
	router.PathPrefix("/ai/{auuid}/{iuuid}").Methods("POST").HandlerFunc(aiPost)
	router.PathPrefix("/ai/{uuid}").Methods("GET").HandlerFunc(aiGet)
	router.PathPrefix("/ai").Methods("GET").HandlerFunc(aiGetAll)
	router.PathPrefix("/ai/{auuid}/{iuuid}").Methods("DELETE").HandlerFunc(aiDelete)
	router.PathPrefix("/ar/{auuid}/{ruuid}").Methods("POST").HandlerFunc(arPost)
	router.PathPrefix("/ar/{uuid}").Methods("GET").HandlerFunc(arGet)
	router.PathPrefix("/ar").Methods("GET").HandlerFunc(arGetAll)
	router.PathPrefix("/ar/{auuid}/{ruuid}").Methods("DELETE").HandlerFunc(arDelete)
	router.PathPrefix("/a/{uuid}").Methods("DELETE").HandlerFunc(aDelete)
	router.PathPrefix("/a/{uuid}").Methods("PUT").HandlerFunc(aPut)
	router.PathPrefix("/a/{uuid}").Methods("GET").HandlerFunc(aGet)
	router.PathPrefix("/a").Methods("GET").HandlerFunc(aGetAll)
	router.PathPrefix("/a").Methods("POST").HandlerFunc(aPost)
	router.PathPrefix("/r/{uuid}").Methods("DELETE").HandlerFunc(rDelete)
	router.PathPrefix("/r/{uuid}").Methods("PUT").HandlerFunc(rPut)
	router.PathPrefix("/r/{uuid}").Methods("GET").HandlerFunc(rGet)
	router.PathPrefix("/r").Methods("GET").HandlerFunc(rGetAll)
	router.PathPrefix("/r").Methods("POST").HandlerFunc(rPost)
	router.PathPrefix("/i/{uuid}").Methods("DELETE").HandlerFunc(iDelete)
	router.PathPrefix("/i/{uuid}").Methods("PUT").HandlerFunc(iPut)
	router.PathPrefix("/i/{uuid}").Methods("GET").HandlerFunc(iGet)
	router.PathPrefix("/i").Methods("GET").HandlerFunc(iGetAll)
	router.PathPrefix("/i").Methods("POST").HandlerFunc(iPost)
	router.PathPrefix("/z/{id}").Methods("GET").HandlerFunc(zGet)
	router.PathPrefix("/t").Methods("GET").HandlerFunc(tGet)
	router.PathPrefix("/").HandlerFunc(b)
	http.Handle("/", router)
	if len(*certFile) != 0 && len(*keyFile) != 0 {
		log.Fatal(http.ListenAndServeTLS(*hostPort, *certFile, *keyFile, has_or_will_get_root(has_or_will_get_token(http.DefaultServeMux))))
	} else {
		log.Fatal(http.ListenAndServe(*hostPort, has_or_will_get_root(has_or_will_get_token(http.DefaultServeMux))))
	}
}

func ensureRoot() {
	reply, err := redisb.Do(c, "EVAL", `
                local cursor = "0"
                local ruuids = nil
                local done = false
                repeat
                        if redis.call("EXISTS", "ROLE:LIST") ~= 0 then
                                local result = redis.call("SSCAN", "ROLE:LIST", cursor)
                                cursor = result[1]
                                ruuids = result[2]
                                for i, ruuid in ipairs(ruuids) do
                                        if redis.call("GET", "ROLE:"..ruuid) == '"root"' then
                                                return 1
                                        end
                                end
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return 0`, "0")
	if err != nil {
		log.Fatalln("Unable to ensure existence of root: with error:", err)
	}
	if result, ok := reply.(int64); !ok {
		log.Fatalln("Unable to ensure existence of root: in conversion:", ok, reply)
	} else if result == 1 {
		log.Println("Root role exists - assuming root exists.")
		return
	}
	iuuid := genUUID()
	ipassword := genUUID()
	// TODO - add a way for root to bcrypt it's password when it's ready
	auuid := genUUID()
	ruuid := genUUID()
	_, err = redisb.Do(c, "EVAL", `
                        redis.call("SADD", "IDENTITY:LIST", ARGV[1])
                        redis.call("SET", "IDENTITY:"..ARGV[1], '["root", "'..ARGV[2]..'"]')
                        redis.call("SADD", "UNIQUE:IDENTITY", '"root"')
                        redis.call("SET", "IDENTITY:ACTOR:"..ARGV[1], ARGV[3])
                        redis.call("SADD", "ACTOR:ROLE:"..ARGV[3], ARGV[4])
                        redis.call("SET", "ROLE:"..ARGV[4], '"root"')
                        redis.call("SADD", "ROLE:LIST", ARGV[4])
                        redis.call("SADD", "ROOT", ARGV[1])
                        redis.call("SADD", "ROOT", ARGV[3])
                        redis.call("SADD", "ROOT", ARGV[4])
                        `, "0", iuuid, ipassword, auuid, ruuid)
	if err != nil {
		log.Fatalln("Unable to ensure existence of root:", err)
	}
	log.Println("Root created.")
}

// TODO - add a way for root to bcrypt it's password when it's ready
func involvesRoot(uuid string) bool {
	if len(uuid) == 0 {
		return false
	}
	reply, err := redisb.Do(c, "SISMEMBER", "ROOT", uuid)
	if err != nil {
		log.Fatalf("Unable to protect root:", err)
	}
	isMember, ok := reply.(bool)
	if !ok {
		log.Fatalf("Unable to protect root: failed to convert:", ok)
	}
	return isMember
}

func has_or_will_get_token(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (strings.HasPrefix(r.URL.Path, "/t") && r.Method == "GET") || isToken(tuuidFrom(r)) {
			h.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}

func isToken(tuuid string) bool {
	reply, err := redisb.Do(c, "GET", "TOKEN:"+tuuid)
	return err == nil && reply != nil
}

func tuuidFrom(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
}

func has_or_will_get_root(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				w.WriteHeader(http.StatusForbidden)
			}
		}()
		if (strings.HasPrefix(r.URL.Path, "/t") && r.Method == "GET") || requestHasRole(r, `"root"`) {
			h.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	})
}

func modifies_root(w http.ResponseWriter, r *http.Request) (result error) {
	defer func() {
		if r := recover(); r != nil {
			w.WriteHeader(http.StatusBadRequest)
			result = fmt.Errorf("Failed in check for root modification: %s", r)
		}
	}()
	if involvesRoot(mux.Vars(r)["uuid"]) ||
		involvesRoot(mux.Vars(r)["auuid"]) ||
		involvesRoot(mux.Vars(r)["iuuid"]) ||
		involvesRoot(mux.Vars(r)["ruuid"]) ||
		involvesRoot(mux.Vars(r)["id"]) {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("Attempt to modify root: %s", r)
	}
	return nil
}

func requestHasRole(r *http.Request, role string) bool {
	for _, v := range rolesFrom(actorFrom(identityFrom(tuuidFrom(r)))) {
		if v == role {
			return true
		}
	}
	return false
}

func rolesFrom(auuid string) []string {
	reply, err := redisb.Do(c, "EVAL", `
                local c = {}
                local cursor = "0"
                local ruuids = nil
                local done = false
                repeat
                        local result = redis.call("SSCAN", "ACTOR:ROLE:"..ARGV[1], cursor)
                        cursor = result[1]
                        ruuids = result[2]
                        for i, ruuid in ipairs(ruuids) do
                                table.insert(c, redis.call("GET", "ROLE:"..ruuid))
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
		return c`, "0", auuid)
	if err != nil {
		return nil
	}
	result, ok := reply.([]string)
	if !ok {
		return nil
	}
	return result
}

func actorFrom(iuuid string) string {
	auuid, err := get("IDENTITY:ACTOR:" + iuuid)
	if err != nil {
		log.Panic("Unable to get actor from identity: ", err)
	}
	return auuid
}

func identityFrom(tuuid string) string {
	iuuid, err := get("TOKEN:" + tuuid)
	if err != nil {
		log.Panic("Unable to get identity from token: ", err)
	}
	return iuuid
}

func b(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }

func jsonFrom(r *http.Request, prefix string) ([]byte, error) {
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("Zero-length bodies are bad requests.")
	}
	switch prefix {
	case "IDENTITY":
		var a = []interface{}{}
		err = json.Unmarshal(b, &a)
	case "ACTOR":
		var m map[string]interface{}
		err = json.Unmarshal(b, &m)
	case "ROLE":
		var s = ""
		err = json.Unmarshal(b, &s)
	}
	return b, err
}

func get(k string) (string, error) {
	reply, err := redisb.Do(c, "GET", k)
	if err == nil && reply != nil {
		if result, ok := reply.(string); ok {
			return result, nil
		} else {
			return "", errors.New("Failed to get: " + k)
		}
	} else {
		return "", err
	}
}

func getr(k string) ([]string, error) {
	reply, err := redisb.Do(c, "GET", k)
	if err == nil {
		if tmp, ok := reply.([]byte); ok {
			var result = []string{}
			err = json.Unmarshal(tmp, &result)
			if err != nil {
				return nil, err
			}
			result[1] = ""
			return result, nil
		} else {
			return nil, errors.New("Failed to getr: " + k)
		}
	} else {
		return nil, err
	}
}

func getl(w http.ResponseWriter, r *http.Request, la string, lb string, lc string) {
	reply, err := redisb.Do(c, "EVAL", la, lb, lc)
	if err == nil {
		if result, ok := reply.(string); ok {
			fmt.Fprint(w, result)
		} else {
			log.Println("Failed to convert eval to string: failed conversion:", ok)
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		log.Println("Failed to run eval:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func smembers(k string) ([]string, error) {
	reply, err := redisb.Do(c, "SMEMBERS", k)
	if err == nil {
		if result, ok := reply.([]string); ok {
			return result, nil
		} else {
			return nil, errors.New("Failed to convert")
		}
	} else {
		return nil, err
	}
}

func add(prefix string, value []byte) (string, error) {
	id := ""
	if prefix == "IDENTITY" {
		v := []string{}
		err := json.Unmarshal(value, &v)
		if err != nil {
			return "", err
		}
		id = v[0]
		idCheckReply, err := redisb.Do(c, "SISMEMBER", "UNIQUE:IDENTITY", id)
		if err != nil {
			return "", err
		}
		if exists, ok := idCheckReply.(bool); !ok || exists {
			return "", errors.New(NON_UNIQUE_IDENTITY)
		}
	}
	if prefix == "ROLE" {
		roleCheckReply, err := redisb.Do(c, "SISMEMBER", "UNIQUE:ROLE", string(value))
		if err != nil {
			return "", err
		}
		if exists, ok := roleCheckReply.(bool); !ok || exists {
			return "", errors.New(NON_UNIQUE_ROLE)
		}
	}
	uuid := genUUID()
	if prefix == "IDENTITY" {
		tmp := []string{}
		err := json.Unmarshal(value, &tmp)
		if err != nil {
			return "", err
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tmp[1]), 10)
		if err != nil {
			log.Panicf("Unable to encrypt password: %s", err)
		}
		tmp[1] = string(hashedPassword)
		value, err = json.Marshal(tmp)
		if err != nil {
			log.Panicf("Unable to encode encrypted password: %s", err)
		}
	}
	if _, err := redisb.Do(c, "SET", prefix+":"+uuid, string(value)); err != nil {
		return "", err
	}
	if _, err := redisb.Do(c, "SADD", prefix+":LIST", uuid); err != nil {
		return "", err
	}
	if prefix == "IDENTITY" {
		if _, err := redisb.Do(c, "SADD", "UNIQUE:IDENTITY", id); err != nil {
			return "", err
		}
	}
	if prefix == "ROLE" {
		if _, err := redisb.Do(c, "SADD", "UNIQUE:ROLE", string(value)); err != nil {
			return "", err
		}
	}
	return uuid, nil
}

func update(prefix string, uuid string, value []byte) error {
	id := ""
	if prefix == "IDENTITY" {
		v := []string{}
		err := json.Unmarshal(value, &v)
		if err != nil {
			return err
		}
		id = v[0]
		idCheckReply, err := redisb.Do(c, "SISMEMBER", "UNIQUE:IDENTITY", id)
		if err != nil {
			return err
		}
		if exists, ok := idCheckReply.(bool); !ok || exists {
			return errors.New(NON_UNIQUE_IDENTITY)
		}
	}
	if prefix == "ROLE" {
		roleCheckReply, err := redisb.Do(c, "SISMEMBER", "UNIQUE:ROLE", string(value))
		if err != nil {
			return err
		}
		if exists, ok := roleCheckReply.(bool); !ok || exists {
			return errors.New(NON_UNIQUE_ROLE)
		}
	}
	previousID := ""
	if prefix == "IDENTITY" {
		previousReply, err := redisb.Do(c, "GET", "IDENTITY:"+uuid)
		if err != nil {
			return err
		}
		previousb, ok := previousReply.([]byte)
		if !ok {
			return errors.New("Failed to convert")
		}
		idPair := []string{}
		if err := json.Unmarshal(previousb, &idPair); err != nil {
			return err
		}
		previousID = idPair[0]
	}
	previousRole := ""
	if prefix == "ROLE" {
		previousReply, err := redisb.Do(c, "GET", "ROLE:"+uuid)
		if err != nil {
			return err
		}
		previousRoleTmp, ok := previousReply.(string)
		if ok {
			return errors.New("Failed to convert")
		}
		previousRole = previousRoleTmp
	}
	if prefix == "IDENTITY" {
		tmp := []string{}
		err := json.Unmarshal(value, &tmp)
		if err != nil {
			return err
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tmp[1]), 10)
		if err != nil {
			log.Panicf("Unable to encrypt password: %s", err)
		}
		tmp[1] = string(hashedPassword)
		value, err = json.Marshal(tmp)
		if err != nil {
			log.Panicf("Unable to encode encrypted password: %s", err)
		}
	}
	reply, err := redisb.Do(c, "SET", prefix+":"+uuid, string(value), "XX")
	if err != nil {
		return errors.New("Updating failed to check for existence of key")
	}
	if reply == nil {
		return errors.New("Updating requires the key to already exist")
	}
	if prefix == "IDENTITY" {
		idPair := []string{}
		if err := json.Unmarshal(value, &idPair); err != nil {
			return err
		}
		if _, err := redisb.Do(c, "SADD", "UNIQUE:IDENTITY", id); err != nil {
			return err
		}
		if _, err := redisb.Do(c, "SREM", "UNIQUE:IDENTITY", previousID); err != nil {
			return err
		}
	}
	if prefix == "ROLE" {
		if _, err := redisb.Do(c, "SADD", "UNIQUE:ROLE", string(value)); err != nil {
			return err
		}
		if _, err := redisb.Do(c, "SREM", "UNIQUE:ROLE", previousRole); err != nil {
			return err
		}
	}
	return nil
}

func del(prefix string, uuid string) error {
	if _, err := redisb.Do(c, "SREM", prefix+":LIST", uuid); err != nil {
		return err
	}
	id := ""
	if prefix == "IDENTITY" {
		previousReply, err := redisb.Do(c, "GET", "IDENTITY:"+uuid)
		if err != nil {
			return err
		}
		previousb, ok := previousReply.([]byte)
		if !ok {
			return errors.New("Failed conversion")
		}
		idPair := []string{}
		if err := json.Unmarshal(previousb, &idPair); err != nil {
			return err
		}
		id = idPair[0]
	}
	role := ""
	if prefix == "ROLE" {
		previousReply, err := redisb.Do(c, "GET", "ROLE:"+uuid)
		if err != nil {
			return err
		}
		roleTmp, ok := previousReply.(string)
		if !ok {
			return errors.New("Failed to convert")
		}
		role = roleTmp
	}
	if _, err := redisb.Do(c, "DEL", prefix+":"+uuid); err != nil {
		return err
	}
	if prefix == "IDENTITY" {
		auuidReply, err := redisb.Do(c, "GET", "IDENTITY:ACTOR:"+uuid)
		if err != nil {
			return err
		}
		auuid, ok := auuidReply.(string)
		if !ok {
			return errors.New("Failed to convert")
		}
		if _, err := redisb.Do(c, "DEL", "IDENTITY:ACTOR:"+uuid); err != nil {
			return err
		}
		if _, err := redisb.Do(c, "SREM", "ACTOR:IDENTITY:"+auuid, uuid); err != nil {
			return err
		}
		if _, err := redisb.Do(c, "SREM", "UNIQUE:IDENTITY", id); err != nil {
			return err
		}
	}
	if prefix == "ROLE" {
		if _, err := redisb.Do(c, "SREM", "UNIQUE:ROLE", role); err != nil {
			return err
		}
	}
	if prefix == "ACTOR" {
		iuuidsReply, err := redisb.Do(c, "SMEMBERS", "ACTOR:IDENTITY:"+uuid)
		if err != nil {
			return err
		}
		iuuids, ok := iuuidsReply.([]string)
		if !ok {
			return errors.New("Failed to convert")
		}
		if _, err := redisb.Do(c, "DEL", "ACTOR:IDENTITY:"+uuid); err != nil {
			return err
		}
		for _, iuuid := range iuuids {
			if _, err := redisb.Do(c, "DEL", "IDENTITY:ACTOR:"+iuuid); err != nil {
				return err
			}
			idReply, err := redisb.Do(c, "GET", "IDENTITY:"+iuuid)
			if err != nil {
				return err
			}
			idb, ok := idReply.([]byte)
			if !ok {
				return err
			}
			idPair := []string{}
			if err := json.Unmarshal(idb, &idPair); err != nil {
				return err
			}
			id = idPair[0]
			if _, err := redisb.Do(c, "SREM", "UNIQUE:IDENTITY", id); err != nil {
				return err
			}
		}
	}
	return nil
}

func genericPost(w http.ResponseWriter, r *http.Request, prefix string) {
	if modifies_root(w, r) != nil {
		return
	}
	b, err := jsonFrom(r, prefix)
	if err != nil {
		log.Printf("POSTing to '%s' requires a valid JSON structure as the body", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if tmp, err := add(prefix, b); err != nil {
		if err.Error() == NON_UNIQUE_IDENTITY || err.Error() == NON_UNIQUE_ROLE {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			log.Println("Failed to add record:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		fmt.Fprint(w, tmp)
	}
}

func genericPut(w http.ResponseWriter, r *http.Request, prefix string) {
	if modifies_root(w, r) != nil {
		return
	}
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("Calls to PUT must include a UUID")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b, err := jsonFrom(r, prefix)
	if err != nil {
		log.Printf("PUTing to '%s' requires a valid JSON object as the body", r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := update(prefix, uuid, b); err != nil {
		if err.Error() == NON_UNIQUE_IDENTITY || err.Error() == NON_UNIQUE_ROLE {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func genericGetAll(w http.ResponseWriter, r *http.Request, k string) {
	getl(w, r, `
                local c = {}
                local cursor = "0"
                local done = false
                repeat
                        local r = redis.call('SSCAN', ARGV[1]..':LIST', cursor)
                        cursor = r[1]
                        for i,k in ipairs(r[2]) do
                                local v = redis.call('GET', ARGV[1]..':'..k)
                                if v then c[k] = v end
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return cjson.encode(c)`, "0", k)
}

func identityGetAll(w http.ResponseWriter, r *http.Request, k string) {
	getl(w, r, `
                local c = {}
                local cursor = "0"
                local done = false
                repeat
                        local r = redis.call('SSCAN', ARGV[1]..':LIST', cursor)
                        cursor = r[1]
                        for i,k in ipairs(r[2]) do
                                local v = redis.call('GET', ARGV[1]..':'..k)
                                if v then
                                        local tmp = cjson.decode(v)
                                        tmp[2] = ""
                                        v = cjson.encode(tmp)
                                        c[k]=v
                                end
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return cjson.encode(c)`, "0", k)
}

func genericGet(w http.ResponseWriter, r *http.Request, k string) {
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("Specific calls to GET must include a uuid")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	o, err := get(k + ":" + uuid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		fmt.Fprintf(w, o)
	}
}

func identityGet(w http.ResponseWriter, r *http.Request, k string) {
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("Specific calls to GET must include a uuid")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	o, err := getr(k + ":" + uuid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		j, err := json.Marshal(o)
		if err != nil {
			log.Println("Failed to marshal to json:", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			fmt.Fprintf(w, string(j))
		}
	}
}

func genericDelete(w http.ResponseWriter, r *http.Request, k string) {
	if modifies_root(w, r) != nil {
		return
	}
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("Calls to DELETE must include a uuid")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err := del(k, uuid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

func aPost(w http.ResponseWriter, r *http.Request)   { genericPost(w, r, "ACTOR") }
func aGetAll(w http.ResponseWriter, r *http.Request) { genericGetAll(w, r, "ACTOR") }
func aGet(w http.ResponseWriter, r *http.Request)    { genericGet(w, r, "ACTOR") }
func aPut(w http.ResponseWriter, r *http.Request)    { genericPut(w, r, "ACTOR") }
func aDelete(w http.ResponseWriter, r *http.Request) { genericDelete(w, r, "ACTOR") }

func rPost(w http.ResponseWriter, r *http.Request)   { genericPost(w, r, "ROLE") }
func rGetAll(w http.ResponseWriter, r *http.Request) { genericGetAll(w, r, "ROLE") }
func rGet(w http.ResponseWriter, r *http.Request)    { genericGet(w, r, "ROLE") }
func rPut(w http.ResponseWriter, r *http.Request)    { genericPut(w, r, "ROLE") }
func rDelete(w http.ResponseWriter, r *http.Request) { genericDelete(w, r, "ROLE") }

func iPost(w http.ResponseWriter, r *http.Request)   { genericPost(w, r, "IDENTITY") }
func iGetAll(w http.ResponseWriter, r *http.Request) { identityGetAll(w, r, "IDENTITY") }
func iGet(w http.ResponseWriter, r *http.Request)    { identityGet(w, r, "IDENTITY") }
func iPut(w http.ResponseWriter, r *http.Request)    { genericPut(w, r, "IDENTITY") }
func iDelete(w http.ResponseWriter, r *http.Request) { genericDelete(w, r, "IDENTITY") }

func aiPost(w http.ResponseWriter, r *http.Request) {
	if modifies_root(w, r) != nil {
		return
	}
	auuid := mux.Vars(r)["auuid"]
	if len(auuid) == 0 {
		log.Println("POSTing to '/ai' requires an auuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	auuidReply, err := redisb.Do(c, "EXISTS", "ACTOR:"+auuid)
	if err != nil {
		log.Println("POSTing to '/ai' - unable to verify if the given auuid exists:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if auuidExists, ok := auuidReply.(bool); !ok || !auuidExists {
		log.Println("POSTing to '/ai' requires the auuid to already exist.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	iuuid := mux.Vars(r)["iuuid"]
	if len(iuuid) == 0 {
		log.Println("POSTing to '/ai' requires an iuuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	iuuidReply, err := redisb.Do(c, "EXISTS", "IDENTITY:"+iuuid)
	if err != nil {
		log.Println("POSTing to '/ai' - unable to verify if the given iuuid exists:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if iuuidExists, ok := iuuidReply.(bool); !ok || !iuuidExists {
		log.Println("POSTing to '/ai' requires the iuuid to already exist.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := redisb.Do(c, "SADD", "ACTOR:IDENTITY:"+auuid, iuuid); err != nil {
		log.Println("Failed to associate an actor to an identity: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := redisb.Do(c, "SET", "IDENTITY:ACTOR:"+iuuid, auuid); err != nil {
		log.Println("Failed to associate an identity to an actor: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func aiGet(w http.ResponseWriter, r *http.Request) {
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("A specific GET to '/ai' requires a uuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	actorReply, err := redisb.Do(c, "EXISTS", "ACTOR:IDENTITY:"+uuid)
	if err == nil && actorReply != nil {
		actorIdentities, err := smembers("ACTOR:IDENTITY:" + uuid)
		if err == nil {
			result, err := json.Marshal(actorIdentities)
			if err != nil {
				log.Println("Failed to marshal actor:identity to json:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, result)
			return
		}
	}
	identityReply, err := redisb.Do(c, "EXISTS", "IDENTITY:ACTOR:"+uuid)
	if err == nil && identityReply != nil {
		identityActor, err := get("IDENTITY:ACTOR" + uuid)
		if err == nil {
			result, err := json.Marshal(identityActor)
			if err != nil {
				log.Println("Failed to marshal identity:actor to json:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, result)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func aiGetAll(w http.ResponseWriter, r *http.Request) {
	getl(w, r, `
                local c = {}
                local cursor = "0"
                local keys = nil
                local done = false
                repeat
                        local result = redis.call("SCAN",cursor,"MATCH","ACTOR:IDENTITY:*")
                        cursor = result[1]
                        keys   = result[2]
                        for i, key in ipairs(keys) do
                                local auuid = string.gsub(key,"ACTOR:IDENTITY:","",1)
                                c[auuid] = redis.call("SMEMBERS",key)
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return cjson.encode(c)`, "0", "")
}

func aiDelete(w http.ResponseWriter, r *http.Request) {
	if modifies_root(w, r) != nil {
		return
	}
	auuid := mux.Vars(r)["auuid"]
	if len(auuid) == 0 {
		log.Println("DELETEing to '/ai' requires an auuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	iuuid := mux.Vars(r)["iuuid"]
	if len(iuuid) == 0 {
		log.Println("DELETEing to '/ai' requires an iuuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if sremActorIdentity(w, auuid, iuuid) != nil {
		return
	}
	if delIdentityActor(w, iuuid) != nil {
		return
	}
}

func sremActorIdentity(w http.ResponseWriter, auuid string, iuuid string) error {
	if _, err := redisb.Do(c, "SREM", "ACTOR:IDENTITY:"+auuid, iuuid); err != nil {
		log.Println("Failed to delete association between an actor and an identity: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}

func delIdentityActor(w http.ResponseWriter, iuuid string) error {
	if _, err := redisb.Do(c, "DEL", "IDENTITY:ACTOR:"+iuuid); err != nil {
		log.Println("Failed to delete association between an identity and an actor: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}

func arPost(w http.ResponseWriter, r *http.Request) {
	if modifies_root(w, r) != nil {
		return
	}
	auuid := mux.Vars(r)["auuid"]
	if len(auuid) == 0 {
		log.Println("POSTing to '/ar' requires an auuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	auuidReply, err := redisb.Do(c, "EXISTS", "ACTOR:"+auuid)
	if err != nil {
		log.Println("POSTing to '/ar' - unable to verify if the given auuid exists:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if auuidExists, ok := auuidReply.(bool); !ok || !auuidExists {
		log.Println("POSTing to '/ar' requires the auuid to already exist.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ruuid := mux.Vars(r)["ruuid"]
	if len(ruuid) == 0 {
		log.Println("POSTing to '/ar' requires an ruuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ruuidReply, err := redisb.Do(c, "EXISTS", "ROLE:"+ruuid)
	if err != nil {
		log.Println("POSTing to '/ar' - unable to verify if the given ruuid exists:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if ruuidExists, ok := ruuidReply.(bool); !ok || !ruuidExists {
		log.Println("POSTing to '/ar' requires the ruuid to already exist.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := redisb.Do(c, "SADD", "ACTOR:ROLE:"+auuid, ruuid); err != nil {
		log.Println("Failed to associate an actor to a role: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := redisb.Do(c, "SADD", "ROLE:ACTOR:"+ruuid, auuid); err != nil {
		log.Println("Failed to associate a role to an actor: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func arGet(w http.ResponseWriter, r *http.Request) {
	uuid := mux.Vars(r)["uuid"]
	if len(uuid) == 0 {
		log.Println("A specific GET to '/ar' requires a uuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	actorReply, err := redisb.Do(c, "EXISTS", "ACTOR:ROLE:"+uuid)
	if err == nil && actorReply != nil {
		actorRole, err := smembers("ACTOR:ROLE:" + uuid)
		if err == nil {
			result, err := json.Marshal(actorRole)
			if err != nil {
				log.Println("Failed to marshal actor:role to json:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, result)
			return
		}
	}
	roleReply, err := redisb.Do(c, "EXISTS", "ROLE:ACTOR:"+uuid)
	if err == nil && roleReply != nil {
		roleActor, err := smembers("ROLE:ACTOR:" + uuid)
		if err == nil {
			result, err := json.Marshal(roleActor)
			if err != nil {
				log.Println("Failed to marshal role:actor to json:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, result)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func arGetAll(w http.ResponseWriter, r *http.Request) {
	getl(w, r, `
                local c = {}
                local cursor = "0"
                local keys = nil
                local done = false
                repeat
                        local result = redis.call("SCAN",cursor,"MATCH","ACTOR:ROLE:*")
                        cursor = result[1]
                        keys   = result[2]
                        for i, key in ipairs(keys) do
                                local auuid = string.gsub(key,"ACTOR:ROLE:","",1)
                                c[auuid] = redis.call("SMEMBERS",key)
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return cjson.encode(c)`, "0", "")
}

func arDelete(w http.ResponseWriter, r *http.Request) {
	if modifies_root(w, r) != nil {
		return
	}
	auuid := mux.Vars(r)["auuid"]
	if len(auuid) == 0 {
		log.Println("DELETEing to '/ar' requires an auuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ruuid := mux.Vars(r)["ruuid"]
	if len(ruuid) == 0 {
		log.Println("DELETEing to '/ar' requires an ruuid.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := redisb.Do(c, "SREM", "ACTOR:ROLE:"+auuid, ruuid); err != nil {
		log.Println("Failed to associate an actor to a role: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := redisb.Do(c, "SREM", "ROLE:ACTOR:"+ruuid, auuid); err != nil {
		log.Println("Failed to associate a role to an actor: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func zGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if len(id) == 0 {
		log.Println("GETting on '/z' requires an id.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	getl(w, r, `
                local cursor = "0"
                local iuuids = nil
                local done = false
                local auuid = ""
                local ruuids = {}
                repeat
                        local outerResult = redis.call("SSCAN","IDENTITY:LIST",cursor)
                        cursor = outerResult[1]
                        iuuids   = outerResult[2]
                        for i, iuuid in ipairs(iuuids) do
                                if cjson.decode(redis.call("GET", "IDENTITY:"..iuuid))[1] == ARGV[1] then
                                        auuid = redis.call("GET", "IDENTITY:ACTOR:" .. iuuid)
                                        ruuids = redis.call("SMEMBERS", "ACTOR:ROLE:"..auuid)
                                        local result = {}
                                        for ri, ruuid in ipairs(ruuids) do
                                                table.insert(result, redis.call("GET", "ROLE:"..ruuid))
                                        end
                                        return "["..table.concat(result, ",").."]"
                                end
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return nil
                `, "0", id)
}

func tGet(w http.ResponseWriter, r *http.Request) {
	tmp, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
	if err != nil {
		log.Println("Invalid Authorization header provided:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	authHeaderPair := strings.Split(string(tmp), ":")
	reply, err := redisb.Do(c, "EVAL", `
                local cursor = "0"
                local iuuids = nil
                local identityPair = {}
                local done = false
                repeat
                        local result = redis.call("SSCAN", "IDENTITY:LIST", cursor)
                        cursor = result[1]
                        iuuids = result[2]
                        for i, iuuid in ipairs(iuuids) do
                                identityPair = cjson.decode(redis.call("GET", "IDENTITY:"..iuuid))
                                if identityPair[1] == cjson.decode(ARGV[1]) then
                                        return {iuuid, identityPair[2]}
                                end
                        end
                        if cursor == "0" then
                                done = true
                        end
                until done
                return {}`, "0", authHeaderPair[0])
	if err != nil {
		log.Println("Unable to run get token script:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resultPair, ok := reply.([]string)
	if !ok {
		log.Println("Unable to get token: failed to convert")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(resultPair) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	iuuid := resultPair[0]
	givenPassword := ""
	if json.Unmarshal([]byte(authHeaderPair[1]), &givenPassword) != nil {
		log.Println("Unable to unmarshal password from authpair:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hashedPassword := resultPair[1]
	if len(iuuid) == 0 || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(givenPassword)) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tuuid := genUUID()
	_, err = redisb.Do(c, "SET", "TOKEN:"+tuuid, iuuid, "EX", *tokenTTL)
	if err != nil {
		log.Println("Unable to set token:", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Write([]byte(tuuid))
	}
}
