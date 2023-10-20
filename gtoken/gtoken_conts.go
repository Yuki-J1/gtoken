package gtoken

import (
	"fmt"
)

const (
	DefaultLogPrefix = "[GToken]" // 日志前缀

	MiddlewareTypeGroup  = 1
	MiddlewareTypeBind   = 2
	MiddlewareTypeGlobal = 3

	CacheModeCache   = 1
	CacheModeRedis   = 2
	CacheModeFile    = 3
	CacheModeFileDat = "gtoken.dat"

	DefaultRefresTokenTimeout = 10 * 24 * 60 * 60 * 1000
	DefaultAccessTokenTimeout = 3 * 60 * 60 * 1000
	DefaultEncryptKey         = "1234567891234567891234567891"
	DefaultAuthFailMsg        = "请求错误或登录超时"

	TraceId = "d5dfce77cdff812161134e55de3c5207"

	KeyUserKey     = "userKey"
	KeyRefreshTime = "refreshTime"
	KeyCreateTime  = "createTime"
	KeyUuid        = "uuid"
	KeyData        = "data"
	KeyToken       = "token"
)

// Meg
const (
	MsgErrCacheNoFound = "cache no found"
	MsgLogoutSucc      = "Logout success"
	MsgErrInitFail     = "InitConfig fail"
	MsgErrNotSet       = "%s not set, error"
	MsgErrUserKeyEmpty = "userKey is empty"
	MsgErrReqMethod    = "request method is error! "
	MsgErrTokenEncrypt = "token encrypt error"
	MsgErrTokenDecode  = "token decode error"
)

func msgLog(msg string, params ...interface{}) string {
	if len(params) == 0 {
		return DefaultLogPrefix + msg
	}
	return DefaultLogPrefix + fmt.Sprintf(msg, params...)
}
