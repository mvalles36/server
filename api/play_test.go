// ... [imports unchanged]
package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/slotopol/server/api"
	"github.com/slotopol/server/cmd"
	cfg "github.com/slotopol/server/config"

	"github.com/gin-gonic/gin"
)

// ... [betset and sumset unchanged]

func ping(t *testing.T, r *gin.Engine) {
	// ... [unchanged]
}

func post(t *testing.T, r *gin.Engine, path string, token string, arg any) (ret gin.H) {
	// ... [unchanged]
}

func TestPlay(t *testing.T) {
	var arg, ret gin.H
	var admtoken, usrtoken string
	var gid, cid uint64
	var uid uint64 = 3
	var wallet, gain float64
	var fsr int

	cfg.CfgPath = "../appdata"
	if err := cmd.Init(); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	var r = gin.New()
	r.HandleMethodNotAllowed = true
	api.SetupRouter(r)

	ping(t, r)

	// Sign-in admin
	arg = gin.H{
		"email":  "admin@example.org",
		"secret": "0YBoaT",
	}
	ret = post(t, r, "/signin", "", arg)
	admtoken = ret["access"].(string)
	t.Logf("[sign-in] admin")

	// Create new club
	arg = gin.H{
		"name":  "Test Club",
		"theme": "default",
	}
	ret = post(t, r, "/club/new", admtoken, arg)
	cid = uint64(ret["cid"].(float64))
	t.Logf("[club/new] cid: %d", cid)

	// Sign-in player
	arg = gin.H{
		"email":  "player@example.org",
		"secret": "iVI05M",
	}
	ret = post(t, r, "/signin", "", arg)
	usrtoken = ret["access"].(string)
	t.Logf("[sign-in] player")

	// Join game
	arg = gin.H{
		"cid":   cid,
		"uid":   uid,
		"alias": "Novomatic / Dolphins Pearl",
	}
	ret = post(t, r, "/game/new", usrtoken, arg)
	gid = uint64(ret["gid"].(float64))
	wallet = ret["wallet"].(float64)
	t.Logf("[game/new] gid: %d, wallet: %.2f", gid, wallet)

	var bet, sel = 1., 5
	post(t, r, "/slot/bet/set", usrtoken, gin.H{"gid": gid, "bet": bet})
	post(t, r, "/slot/sel/set", usrtoken, gin.H{"gid": gid, "sel": sel})

	for range 100 {
		if wallet < bet*float64(sel) {
			var sum float64
			for wallet+sum < bet*float64(sel) {
				sum = sumset[rand.N(len(sumset))]
			}
			ret = post(t, r, "/prop/wallet/add", admtoken, gin.H{"cid": cid, "uid": uid, "sum": sum})
			wallet = ret["wallet"].(float64)
		}

		ret = post(t, r, "/slot/spin", usrtoken, gin.H{"gid": gid})
		var game = ret["game"].(map[string]any)
		if v, ok := game["gain"]; ok {
			gain = v.(float64)
		}
		if v, ok := game["fsr"]; ok {
			fsr = int(v.(float64))
		}
		wallet = ret["wallet"].(float64)

		if fsr > 0 {
			continue
		}

		if gain > 0 && rand.Float64() < 0.3 {
			for {
				ret = post(t, r, "/slot/doubleup", usrtoken, gin.H{"gid": gid, "mult": 2, "half": rand.Float64() < 0.25})
				gain = ret["gain"].(float64)
				wallet = ret["wallet"].(float64)
				if gain == 0 || rand.Float64() < 0.5 {
					post(t, r, "/slot/collect", usrtoken, gin.H{"gid": gid})
					break
				}
			}
		}

		if rand.Float64() < 1./25. {
			bet = betset[rand.N(len(betset))]
			post(t, r, "/slot/bet/set", usrtoken, gin.H{"gid": gid, "bet": bet})
		}
		if rand.Float64() < 1./25. {
			sel = 3 + rand.N(8)
			post(t, r, "/slot/sel/set", usrtoken, gin.H{"gid": gid, "sel": sel})
		}
	}
}