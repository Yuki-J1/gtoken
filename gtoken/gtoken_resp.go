package gtoken

import (
	"encoding/json"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/util/gconv"
)

const (
	SUCCESS      = 0    // 正常
	FAIL         = -1   // 失败
	ERROR        = -99  // 异常
	UNAUTHORIZED = -401 // 未认证
)

type Resp struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
	Data   g.Map  `json:"data"`
}

// Success 获取Data值转字符串
func (resp Resp) Success() bool {
	return resp.Status == SUCCESS
}

// DataString 获取Data转字符串
func (resp Resp) DataString() string {
	return gconv.String(resp.Data)
}

// DataInt 获取Data转Int
func (resp Resp) DataInt() int {
	return gconv.Int(resp.Data)
}

// GetString 获取Data值转字符串
func (resp Resp) GetString(key string) string {
	return gconv.String(resp.Get(key))
}

// GetInt 获取Data值转Int
func (resp Resp) GetInt(key string) int {
	return gconv.Int(resp.Get(key))
}

// Get 获取Data值
func (resp Resp) Get(key string) *gvar.Var {
	m := gconv.Map(resp.Data)
	if m == nil {
		return nil
	}
	return gvar.New(m[key])
}

func (resp Resp) Json() string {
	str, _ := json.Marshal(resp)
	return string(str)
}

// Succ 成功
func Succ(msg string) Resp {
	return Resp{SUCCESS, msg, g.Map{}}
}

// Fail 失败
func Fail(msg string) Resp {
	return Resp{FAIL, msg, g.Map{}}
}

// FailData 失败设置Data
func FailData(msg string, data interface{}) Resp {
	return Resp{FAIL, msg, g.Map{}}
}

// Error 错误
func Error(msg string) Resp {
	return Resp{ERROR, msg, g.Map{}}
}

// ErrorData 错误设置Data
func ErrorData(msg string, data interface{}) Resp {
	return Resp{ERROR, msg, g.Map{}}
}

// Unauthorized 认证失败
func Unauthorized(msg string, data interface{}) Resp {
	return Resp{UNAUTHORIZED, msg, g.Map{}}
}
