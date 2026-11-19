package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Sign computes the request signature:
// HMAC-SHA256(key, agentID \n timestamp \n METHOD \n path \n sha256(body)).
func Sign(keyHex, agentID string, ts int64, method, path string, body []byte) string {
	key, _ := hex.DecodeString(keyHex)
	bh := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(agentID + "\n" + strconv.FormatInt(ts, 10) + "\n" + method + "\n" + path + "\n" + hex.EncodeToString(bh[:])))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature and that the timestamp is within the allowed skew.
func Verify(keyHex, agentID, tsStr, method, path string, body []byte, sig string, skew time.Duration) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	d := time.Since(time.Unix(ts, 0))
	if d > skew || d < -skew {
		return false
	}
	want := Sign(keyHex, agentID, ts, method, path, body)
	return hmac.Equal([]byte(want), []byte(sig))
}
