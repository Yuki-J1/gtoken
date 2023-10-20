package gtoken

import (
	"context"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/crypto/gaes"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/gogf/gf/v2/util/grand"
	"net/http"
	"strings"
	"time"
)

// GfToken gtoken结构体
type GfToken struct {
	// 中间件类型 1 GroupMiddleware 2 BindMiddleware  3 GlobalMiddleware
	MiddlewareType uint
	// 全局模式时候使用，绑定*ghttp.Server实例 默认空
	ServerName string
	// 缓存模式 1gcache 2gredis 3fileCach  默认1 gcache , 通常建议使用 2 gredis
	CacheMode int8
	// 登陆模式 1单端登录 2多端登录 默认1
	LoginMode int8
	// 端标识 默认 PC=1,Android=2,IOS=3 ,单端登录模式下，PC默认端 其他端拒绝
	ClientAlias *ClientAlias
	// 是否开启同端互斥 默认同端互斥1
	IsMutex int8

	// Token加密key
	EncryptKey string
	// 盐范围 默认0,255
	SaltRange [2]int
	// AccessTokenTimeout 默认3h
	AccessTokenTimeout int
	// RefresTokenTimeout 默认不过期
	RefresTokenTimeout int
	// 认证失败中文提示
	AuthFailMsg string

	// 登录路径
	LoginPath string
	// 账号密码验证方法
	//	 PS：库使用者实例化GfToken结构体的时候 必须要自定义此字段，但要返回请求包含的设备标识和查询到的主键ID
	LoginBeforeFunc func(r *ghttp.Request) (int8, int8)
	// 登录返回方法
	// 	PS：可自定义，没有自定义使用默认
	LoginAfterFunc func(r *ghttp.Request, respData Resp)
	// 登出地址
	LogoutPath string
	// 登出验证方法 如果返回true 继续进行登出逻辑（丢弃AccessToken对应的盐），否则结束执行
	//	 PS：可自定义，没有自定义使用默认
	LogoutBeforeFunc func(r *ghttp.Request) bool
	// 登出返回方法
	// 	PS：可自定义，没有自定义使用默认
	LogoutAfterFunc func(r *ghttp.Request, respData Resp)

	// 拦截地址
	AuthPaths g.SliceStr
	// 拦截排除地址
	AuthExcludePaths g.SliceStr
	// 认证验证方法 return true 继续执行，否则结束执行
	// 	PS：可自定义，没有自定义使用默认
	AuthBeforeFunc func(r *ghttp.Request) bool
	// 认证返回方法
	// 	PS：可自定义，没有自定义使用默认
	AuthAfterFunc func(r *ghttp.Request, respData Resp)
}

type ClientAlias struct {
	Default int8 // 你好
	PC      int8 // 你好
	Android int8
	IOS     int8
}

// Login 登录路由规则绑定的handler
func (m *GfToken) Login(r *ghttp.Request) {

	// region ========== LoginBeforeFunc 基本在这里进行用户名密码的验证 ==========

	// 去数据库验证，返回的应该是请求携带的 设备信息，用户主键ID
	device, userid := m.LoginBeforeFunc(r)
	if device == 0 || userid == -1 {
		g.Log().Error(r.Context(), msgLog(MsgErrUserKeyEmpty))
		return
	}
	// endregion

	// region ========== 根据配置文件指定登录模式 进入不同的逻辑 ==========

	/*
		单端 并且 同端互斥
		单端 并且 同端不互斥
		多端 并且 同端互斥
		多端 并且 同端不互斥

		 在单端并且同端互斥情况下：
		 		用户主键ID和设备信息 作为key 从缓存中获取值 (PCRefreshSalt.PCAccessSalt)
		 			如果有值，说明已经登录，弃用之前的Access_token(修改AccessSalt)，重新生成AccessSalt颁发Access_token，并且返回Refresh_token。

		 			如果没有，说明这是此账户第一次在此端登录，生成AccessSalt、RefreshSalt，颁发Access_token Refresh_token。
		 			同时返回Access_token Refresh_token。

		 在单端并且同端不互斥情况下：
		 		用户主键ID和设备信息 作为key 从缓存中获取值 PCRefreshSalt(下标0).PCAccessSalt(下标1)......
					如果有值，说明此用户使用此端登录过，由于采用同端不互斥，所以不需要弃用之前的Access_token，生成新的AccessSalt颁发新的Access_token。
		 			追加到 PCRefreshSalt(下标0).PCAccessSalt(下标1).PCAccessSalt(下标2).....
		 			将颁发的Access_token  和 2 和 RefreshSalt一同返回

		 			如果没有，说明这是此账户第一次在此端登录，生成AccessSalt、RefreshSalt，颁发Access_token Refresh_token。
		 			同时返回Access_token 和 1 和 Refresh_token。

		 在多端并且同端互斥情况下：重复单端并且同端互斥逻辑,只是key不同 key变为 用户主键ID+不同端设备ID
		 在多端并且同端不互斥情况下：重复单端并且同端不互斥逻辑,只是key不同 key变为 用户主键ID+不同端设备ID
	*/

	var gTokenResp Resp
	// 第一版
	/*
		// 检查配置是否开启 单端-同端互斥 (实现过程中有个明显特征 : 盐组大小是固定的 )
		if m.LoginMode == 1 && m.IsMutex == 1 {

			// region ========== 进制除默认端外其他端的登录请求 ==========
			if device != m.ClientAlias.Default {
				r.Response.WriteJson(Fail("单端-同端互斥: 请求发送端不是默认端，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
			Value, err := m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				g.Log().Error(r.Context(), err.Error())
				r.Response.WriteJson(Fail("单端-同端互斥: getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

			if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

				// 生成AccessSalt和RefreshSalt
				// 将RefreshSalt.AccessSalt 保存缓存中
				AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				UserDeviceValue := make([]int, 10)
				UserDeviceValue[1] = AccessSalt
				UserDeviceValue[0] = RefresSalt
				err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
				if err != nil {
					r.Response.WriteJson(Fail("单端-同端互斥: setCache 错误").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 生成Access_token Refresh_token ==========

				// 共32
				// m.EncryptKey 长度为 32-1-n
				// - 长度1
				// gconv.String(AccessSalt) 长度n
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
				g.Log().Info(r.Context(), AccessToken)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("单端-同端互斥: 登录成功")
				gTokenResp.Data = g.Map{
					"AccessToken": AccessToken,
					"RefresToken": RefresToken,
				}
				// 成功

				// endregion

				// endregion
			} else {
				// region ========== 如果查到值，说明是同端登录。同端互斥 ==========

				// 弃用之前的Access_token(修改AccessSalt)，重新生成AccessSalt颁发Access_token，
				// 使用第一次同端登录生成的RefreshSalt 加密Refresh_token。
				// PS: 弃用颁发过的的Access_token(修改AccessSalt)、不弃用之前颁发过的Refresh_token(不修改RefreshSalt)
				// [默认10天Refresh_token过期，颁发过的token都弃用了 你也可以设置不过期(推荐) ]
				// 同端登录 共享RefreshSalt 但是不共享AccessSalt
				Value[1] = grand.N(m.SaltRange[0], m.SaltRange[1])

				err := m.setCache(r.Context(), UserIDDeviceKey, Value)
				if err != nil {
					r.Response.WriteJson(Fail("单端-同端互斥: setCache 错误").Json())
					r.ExitAll()
				}
				if err != nil {
					r.Response.WriteJson(Fail("单端-同端不互斥: setCache err ").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[1]), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("单端-同端互斥: 登录成功")
				gTokenResp.Data = g.Map{
					"AccessToken": AccessToken,
					"RefresToken": RefresToken,
				}
				// endregion

				// endregion
			}

		} else
		// 单端 并且 同端不互斥 (实现过程中有个明显特征 : 盐组大小不是固定而是变化 )
		if m.LoginMode == 1 && m.IsMutex == 2 {
			// region ========== 进制除默认端外其他端的登录请求 ==========
			if device != m.ClientAlias.Default {
				r.Response.WriteJson(Fail("单端-同端不互斥: 请求发送端不是默认端，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
			Value, err := m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail("单端-同端不互斥: getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

			if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

				// 生成AccessSalt和RefreshSalt
				// 将RefreshSalt.AccessSalt 保存缓存中
				AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				var UserDeviceValue []int
				UserDeviceValue[1] = AccessSalt
				UserDeviceValue[0] = RefresSalt
				err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
				if err != nil {
					r.Response.WriteJson(Fail("单端-同端不互斥: setCache 错误").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 生成Access_token Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端不互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端不互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("单端-同端不互斥: 登录成功")
				// 成功

				// endregion

				// endregion
			} else {
				// region ========== 如果查到值，说明是同端登录。同端不互斥 ==========

				// 不弃用之前的Access_token(不丢弃之前的AccessSalt)，重新生成新的AccessSalt颁发新的Access_token，
				// 使用第一次同端登录生成的旧RefreshSalt 颁发新Refresh_token。
				// 新AccessSalt 添加到Salt组 组样子  RefreshSalt.AccessSal.AccessSal.AccessSal... 以此类推长度为10 TODO:暂定10

				// 检查盐组达到上限
				if len(Value) == 10 {
					r.Response.WriteJson(Fail("单端-同端不互斥: 同端登录达到上线10 ").Json())
					r.ExitAll()
				}
				Value[len(Value)-1] = grand.N(m.SaltRange[0], m.SaltRange[1])

				err := m.setCache(r.Context(), UserIDDeviceKey, Value)
				if err != nil {
					r.Response.WriteJson(Fail("单端-同端不互斥: setCache err ").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  len(Value) - 1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0, // 固定为0

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(), // TODO: Refresh_token 有效期是不是应该不过期 盐组是否应该不过期
				}
				// endregion

				// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[len(Value)-1]), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端不互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("单端-同端不互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("单端-同端不互斥: 登录成功")
				// endregion

				// endregion
			}

		} else
		// 多端 并且 同端互斥
		if m.LoginMode == 2 && m.IsMutex == 1 {

			// region ========== 检查发起请求的端是否 在预设范围内 ==========
			if device != m.ClientAlias.PC || device != m.ClientAlias.Android || device != m.ClientAlias.IOS {
				r.Response.WriteJson(Fail("多端-同端互斥: 请求发送端不是预设的端，端必须在PC Android IOS，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
			Value, err := m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail("多端-同端互斥: getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

			if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

				// 生成AccessSalt和RefreshSalt
				// 将RefreshSalt.AccessSalt 保存缓存中
				AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				var UserDeviceValue []int
				UserDeviceValue[1] = AccessSalt
				UserDeviceValue[0] = RefresSalt
				err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
				if err != nil {
					r.Response.WriteJson(Fail("多端-同端互斥: setCache 错误").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 生成Access_token Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("多端-同端互斥: 登录成功")
				// 成功

				// endregion

				// endregion
			} else {
				// region ========== 如果查到值，说明是同端登录。同端互斥 ==========

				// 弃用之前的Access_token(修改AccessSalt)，重新生成AccessSalt颁发Access_token，
				// 使用第一次同端登录生成的RefreshSalt 加密Refresh_token。
				// PS: 弃用颁发过的的Access_token(修改AccessSalt)、不弃用之前颁发过的Refresh_token(不修改RefreshSalt)
				// [默认10天Refresh_token过期，颁发过的token都弃用了 你也可以设置不过期(推荐) ]
				// 同端登录 共享RefreshSalt 但是不共享AccessSalt
				// 盐槽 盐组len不变
				Value[1] = grand.N(m.SaltRange[0], m.SaltRange[1])

				err := m.setCache(r.Context(), UserIDDeviceKey, Value)
				if err != nil {
					r.Response.WriteJson(Fail("多端-同端互斥: setCache 错误").Json())
					r.ExitAll()
				}
				if err != nil {
					r.Response.WriteJson(Fail("多端-同端互斥: setCache err ").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[1]), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("多端-同端互斥: 登录成功")
				// endregion

				// endregion
			}
		} else {
			// m.LoginMode == 2 && m.IsMutex == 2
			// 多端 并且 同端不互斥

			// region ========== 检查发起请求的端是否 在预设范围内 ==========
			if device != m.ClientAlias.PC || device != m.ClientAlias.Android || device != m.ClientAlias.IOS {
				r.Response.WriteJson(Fail("多端-同端不互斥: 请求发送端不是预设的端，端必须在PC Android IOS，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
			Value, err := m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail("多端-同端不互斥: getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

			if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

				// 生成AccessSalt和RefreshSalt
				// 将RefreshSalt.AccessSalt 保存缓存中
				AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
				var UserDeviceValue []int
				UserDeviceValue[1] = AccessSalt
				UserDeviceValue[0] = RefresSalt
				err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
				if err != nil {
					r.Response.WriteJson(Fail("多端-同端不互斥: setCache 错误").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(),
				}
				// endregion

				// region ========== 生成Access_token Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端不互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端不互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("多端-同端不互斥: 登录成功")
				// 成功

				// endregion

				// endregion
			} else {
				// region ========== 如果查到值，说明是同端登录。同端不互斥 ==========

				// 不弃用之前的Access_token(不丢弃之前的AccessSalt)，重新生成新的AccessSalt颁发新的Access_token，
				// 使用第一次同端登录生成的旧RefreshSalt 颁发新Refresh_token。
				// 新AccessSalt 添加到Salt组 组样子  RefreshSalt.AccessSal.AccessSal.AccessSal... 以此类推长度为10 TODO:暂定10

				// 检查盐组达到上限
				if len(Value) == 10 {
					r.Response.WriteJson(Fail("多端-同端不互斥: 同端登录达到上线10 ").Json())
					r.ExitAll()
				}
				Value[len(Value)-1] = grand.N(m.SaltRange[0], m.SaltRange[1])

				err := m.setCache(r.Context(), UserIDDeviceKey, Value)
				if err != nil {
					r.Response.WriteJson(Fail("多端-同端不互斥: setCache err ").Json())
					r.ExitAll()
				}

				// region ========== 准备Token 未加密前的 负载 ==========
				AccessClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "access",
					"saltslot":  len(Value) - 1,

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 3).Unix(),
				}

				RefresClaims := g.Map{
					"userid":    userid,
					"device":    device,
					"tokentype": "refres",
					"saltslot":  0, // 固定为0

					"role": "admin",
					"exp":  time.Now().Add(time.Hour * 24 * 10).Unix(), // TODO: Refresh_token 有效期是不是应该不过期 盐组是否应该不过期
				}
				// endregion

				// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
				AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[len(Value)-1]), AccessClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端不互斥: AccessToken encrypt error ").Json())
					r.ExitAll()
				}
				RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
				if err != nil {
					g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
					r.Response.WriteJson(Succ("多端-同端不互斥: RefresToken encrypt error ").Json())
					r.ExitAll()
				}
				// endregion

				// region ========== 返回 Access_token Refresh_token ==========
				r.Response.Header().Set("AccessToken", AccessToken)
				r.Response.Header().Set("RefresToken", RefresToken)
				gTokenResp = Succ("多端-同端不互斥: 登录成功")
				// endregion

				// endregion
			}
		}
	*/

	// region ========== 第二版 ==========

	// 判断是否互斥，由于互斥逻辑相似，先分出非互斥和互斥
	if m.IsMutex == 1 {

		Mode := ""
		var UserIDDeviceKey string
		var Value []int
		var err error

		// 判断是单端 还是 多端
		switch m.LoginMode {
		case 1:
			Mode = "单端-同端互斥"

			// region ========== 进制除默认端外其他端的登录请求 ==========
			if device != m.ClientAlias.Default {
				r.Response.WriteJson(Fail(Mode + ": 请求发送端不是默认端，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey = gconv.String(userid) + "-" + gconv.String(device)
			Value, err = m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				g.Log().Error(r.Context(), err.Error())
				r.Response.WriteJson(Fail(Mode + ": getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

		case 2:

			Mode = "多端-同端互斥"

			// region ========== 检查发起请求的端是否 在预设范围内 ==========
			if device != m.ClientAlias.PC || device != m.ClientAlias.Android || device != m.ClientAlias.IOS {
				r.Response.WriteJson(Fail("多端-同端互斥: 请求发送端不是预设的端，端必须在PC Android IOS，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey = gconv.String(userid) + "-" + gconv.String(device)
			Value, err = m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail("多端-同端互斥: getCache 错误").Json())
				r.ExitAll()
			}
			// endregion
		}

		if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
			// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

			// 生成AccessSalt和RefreshSalt
			// 将RefreshSalt.AccessSalt 保存缓存中
			RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
			AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
			UserDeviceValue := make([]int, 10)
			UserDeviceValue[0] = RefresSalt
			UserDeviceValue[1] = AccessSalt
			err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
			if err != nil {
				r.Response.WriteJson(Fail(Mode + ": setCache 错误").Json())
				r.ExitAll()
			}

			// region ========== 准备Token 未加密前的 负载 ==========
			AccessClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "access",
				"saltslot":  1,

				"role": "admin",
				"exp":  time.Now().Add(DefaultAccessTokenTimeout).Unix(),
			}

			RefresClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "refres",
				"saltslot":  0,

				"role": "admin",
			}
			// endregion

			// region ========== 生成Access_token Refresh_token ==========
			AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": AccessToken encrypt error ").Json())
				r.ExitAll()
			}
			RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": RefresToken encrypt error ").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 返回 Access_token Refresh_token ==========
			r.Response.Header().Set("AccessToken", AccessToken)
			r.Response.Header().Set("RefresToken", RefresToken)
			gTokenResp = Succ(Mode + ": 登录成功")
			// 成功

			// endregion

			// endregion
		} else {
			// region ========== 如果查到值，说明是同端登录。同端互斥 ==========

			// 弃用之前的Access_token(修改AccessSalt)，重新生成AccessSalt颁发Access_token，
			// 使用第一次同端登录生成的RefreshSalt 加密Refresh_token。
			// PS: 弃用颁发过的的Access_token(修改AccessSalt)、不弃用之前颁发过的Refresh_token(不修改RefreshSalt)
			// [默认10天Refresh_token过期，颁发过的token都弃用了 你也可以设置不过期(推荐) ]
			// 同端登录 共享RefreshSalt 但是不共享AccessSalt
			// 盐槽 盐组len不变
			Value[1] = grand.N(m.SaltRange[0], m.SaltRange[1])

			err := m.setCache(r.Context(), UserIDDeviceKey, Value)
			if err != nil {
				r.Response.WriteJson(Fail(Mode + ": setCache 错误").Json())
				r.ExitAll()
			}
			if err != nil {
				r.Response.WriteJson(Fail(Mode + ": setCache err ").Json())
				r.ExitAll()
			}

			// region ========== 准备Token 未加密前的 负载 ==========
			AccessClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "access",
				"saltslot":  1,

				"role": "admin",
				"exp":  time.Now().Add(DefaultAccessTokenTimeout).Unix(),
			}

			RefresClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "refres",
				"saltslot":  0,

				"role": "admin",
			}
			// endregion

			// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
			AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[1]), AccessClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": AccessToken encrypt error ").Json())
				r.ExitAll()
			}
			RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": RefresToken encrypt error ").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 返回 Access_token Refresh_token ==========
			r.Response.Header().Set("AccessToken", AccessToken)
			r.Response.Header().Set("RefresToken", RefresToken)
			gTokenResp = Succ(Mode + ": 登录成功")
			// endregion

			// endregion
		}

	} else {

		Mode := ""
		var UserIDDeviceKey string
		var Value []int
		var err error

		// 判断是单端 还是 多端
		switch m.LoginMode {
		case 1:
			Mode = "单端-同端不互斥"

			// region ========== 进制除默认端外其他端的登录请求 ==========
			if device != m.ClientAlias.Default {
				r.Response.WriteJson(Fail(Mode + ": 请求发送端不是默认端，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey = gconv.String(userid) + "-" + gconv.String(device)
			Value, err = m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail(Mode + ": getCache 错误").Json())
				r.ExitAll()
			}
			// endregion

		case 2:
			Mode = "多端-同端不互斥"

			// region ========== 检查发起请求的端是否 在预设范围内 ==========
			if device != m.ClientAlias.PC || device != m.ClientAlias.Android || device != m.ClientAlias.IOS {
				r.Response.WriteJson(Fail(Mode + ": 请求发送端不是预设的端，端必须在PC Android IOS，不允许登录").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 检查 用户在此端是否有过登录 ==========
			UserIDDeviceKey = gconv.String(userid) + "-" + gconv.String(device)
			Value, err = m.getCache(r.Context(), UserIDDeviceKey)
			if err != nil && !gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
				r.Response.WriteJson(Fail(Mode + ": getCache 错误").Json())
				r.ExitAll()
			}
			// endregion
		}

		if gerror.Equal(err, gerror.New(MsgErrCacheNoFound)) {
			// region ========== 如果查不到值 说明此账号第一次在此端登录 ==========

			// 生成AccessSalt和RefreshSalt
			// 将RefreshSalt.AccessSalt 保存缓存中
			RefresSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
			AccessSalt := grand.N(m.SaltRange[0], m.SaltRange[1])
			UserDeviceValue := make([]int, 10)
			UserDeviceValue[0] = RefresSalt
			UserDeviceValue[1] = AccessSalt
			err := m.setCache(r.Context(), UserIDDeviceKey, UserDeviceValue)
			if err != nil {
				r.Response.WriteJson(Fail(Mode + ": setCache 错误").Json())
				r.ExitAll()
			}

			// region ========== 准备Token 未加密前的 负载 ==========
			AccessClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "access",
				"saltslot":  1,

				"role": "admin",
				"exp":  time.Now().Add(DefaultAccessTokenTimeout).Unix(),
			}

			RefresClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "refres",
				"saltslot":  0,

				"role": "admin",
			}
			// endregion

			// region ========== 生成Access_token Refresh_token ==========
			AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(AccessSalt), AccessClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": AccessToken encrypt error ").Json())
				r.ExitAll()
			}
			RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(RefresSalt), RefresClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": RefresToken encrypt error ").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 返回 Access_token Refresh_token ==========
			r.Response.Header().Set("AccessToken", AccessToken)
			r.Response.Header().Set("RefresToken", RefresToken)
			gTokenResp = Succ(Mode + ": 登录成功")
			// 成功

			// endregion

			// endregion
		} else {
			// region ========== 如果查到值，说明是同端登录。同端不互斥 ==========

			// 不弃用之前的Access_token(不丢弃之前的AccessSalt)，重新生成新的AccessSalt颁发新的Access_token，
			// 使用第一次同端登录生成的旧RefreshSalt 颁发新Refresh_token。
			// 新AccessSalt 添加到Salt组 组样子  RefreshSalt.AccessSal.AccessSal.AccessSal... 以此类推长度为10 TODO:暂定10

			// 检查盐组达到上限
			if len(Value) == 10 {
				r.Response.WriteJson(Fail(Mode + ": 同端登录达到上线10 ").Json())
				r.ExitAll()
			}
			Value[len(Value)] = grand.N(m.SaltRange[0], m.SaltRange[1])

			err := m.setCache(r.Context(), UserIDDeviceKey, Value)
			if err != nil {
				r.Response.WriteJson(Fail(Mode + ": setCache err ").Json())
				r.ExitAll()
			}

			// region ========== 准备Token 未加密前的 负载 ==========
			AccessClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "access",
				"saltslot":  len(Value) - 1,

				"role": "admin",
				"exp":  time.Now().Add(DefaultAccessTokenTimeout).Unix(),
			}

			RefresClaims := g.Map{
				"userid":    userid,
				"device":    device,
				"tokentype": "refres",
				"saltslot":  0, // 固定为0

				"role": "admin",
			}
			// endregion

			// region ========== 新Access盐生成Access_token 旧Refresh盐生成Refresh_token ==========
			AccessToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[len(Value)-1]), AccessClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s AccessToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": AccessToken encrypt error ").Json())
				r.ExitAll()
			}
			RefresToken, err := m.genToken(r.Context(), m.EncryptKey+"-"+gconv.String(Value[0]), RefresClaims)
			if err != nil {
				g.Log().Error(r.Context(), msgLog("%s RefresToken encrypt error", gconv.String(userid)), err)
				r.Response.WriteJson(Succ(Mode + ": RefresToken encrypt error ").Json())
				r.ExitAll()
			}
			// endregion

			// region ========== 返回 Access_token Refresh_token ==========
			r.Response.Header().Set("AccessToken", AccessToken)
			r.Response.Header().Set("RefresToken", RefresToken)
			gTokenResp = Succ(Mode + ": 登录成功")
			// endregion

			// endregion
		}

	}
	// endregion

	// endregion

	// region ========== LoginAfterFunc ==========
	m.LoginAfterFunc(r, gTokenResp)
	// endregion
}

// Logout 登出路由规则绑定的handler
func (m *GfToken) Logout(r *ghttp.Request) {
	if !m.LogoutBeforeFunc(r) {
		return
	}

	// 1. 获取AccessToken
	AT := m.GetAccessToken(r)
	if AT == "" {
		r.Response.WriteJson(Fail("AccessToken is empty").Json())
		r.ExitAll()
	}
	// 2. 认证AccessToken 并且返回用户主键ID 设备信息 盐组位置
	Isverified, UserID, Device, saltslot := m.validTokenAndReturn(r.Context(), AT)
	if Isverified == false {
		r.Response.WriteJson(Fail("validTokenAndReturn err").Json())
		r.ExitAll()
	}

	// 3. 用户主键ID 设备信息 查值，如果互斥 删除盐组下标为1的值 弃用AccessToken 如果不互斥 删除指定盐组位置下标为的值 弃用AccessToken
	UserIDDeviceKey := gconv.String(UserID) + "-" + gconv.String(Device)
	Value, err := m.getCache(r.Context(), UserIDDeviceKey)
	if err != nil {
		r.Response.WriteJson(Fail("getCache err").Json())
		r.ExitAll()
	}
	if m.IsMutex == 1 {
		Value[1] = -1
	} else {
		Value[saltslot] = -1
	}

	m.LogoutAfterFunc(r, Succ("Logout is Success"))
}

// AuthMiddleware 认证拦截中间件
func (m *GfToken) authMiddleware(r *ghttp.Request) {
	urlPath := r.URL.Path
	// 判断路径是否需要进行认证拦截 return true 需要认证
	if !m.AuthPath(r.Context(), urlPath) {
		// 如果不需要认证，继续
		r.Middleware.Next()
		return
	}

	// 不需要认证，直接下一步
	// （认证之前验证方法 return true 继续执行，否则结束执行）
	if !m.AuthBeforeFunc(r) {
		r.Middleware.Next()
		return
	}

	AT := m.GetAccessToken(r)
	if AT == "" {
		r.Response.WriteJson(Fail("AccessToken is empty").Json())
		r.ExitAll()
	}
	if !m.validToken(r.Context(), AT) {
		r.Response.WriteJson(Fail("validToken is Fail").Json())
		r.ExitAll()
	}
	// （认证之后）
	m.AuthAfterFunc(r, Succ("validToken is Success"))
}

// AuthPath 判断请求的路径是否需要进行认证拦截 return true 需要认证
func (m *GfToken) AuthPath(ctx context.Context, urlPath string) bool {
	// http请求 urlPath 是否以/结尾 , 如果以/结尾去掉/
	if strings.HasSuffix(urlPath, "/") {
		urlPath = gstr.SubStr(urlPath, 0, len(urlPath)-1)
	}
	// 分组拦截，登录接口不拦截
	if m.MiddlewareType == MiddlewareTypeGroup {
		// m.LoginPath不为空 并且 urlPath以m.LoginPath结尾
		// 或者
		// m.LogoutPath不为空 并且 urlPath以m.LogoutPath结尾
		// 说明此http请求是登录或者登出请求，不需要拦截
		if (m.LoginPath != "" && /* 与 x 并且 */ gstr.HasSuffix(urlPath, m.LoginPath)) ||
			(m.LogoutPath != "" && gstr.HasSuffix(urlPath, m.LogoutPath)) {
			return false
		}
	}

	// 全局处理，认证路径拦截处理
	if m.MiddlewareType == MiddlewareTypeGlobal {
		var authFlag bool
		// 遍历 m.AuthPaths 检查每个需要拦截的地址,后缀是否为/*，如果是则去掉/*后缀
		for _, authPath := range m.AuthPaths {
			tmpPath := authPath
			if strings.HasSuffix(tmpPath, "/*") {
				tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-2)
			}
			// 如果http请求urlPath的前缀是 tmpPath 说明是需要拦截
			if gstr.HasPrefix(urlPath, tmpPath) {
				authFlag = true
				break
			}
		}
		// 如果不需要拦截，直接返回
		if !authFlag {
			return false
		}
	}

	// 排除路径处理，到这里nextFlag为true
	for _, excludePath := range m.AuthExcludePaths {
		tmpPath := excludePath
		// 排除的规则后缀如果包含/*, 去掉/*
		// http请求的urlPath前缀是排除的规则,说明不需要拦截
		if strings.HasSuffix(tmpPath, "/*") {
			tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-2)
			if gstr.HasPrefix(urlPath, tmpPath) {
				return false
			}
		} else
		// 排除的规则后缀如果包含 / ,去除 /
		// http请求的urlPath == 排除的规则,说明不需要拦截
		{
			if strings.HasSuffix(tmpPath, "/") {
				tmpPath = gstr.SubStr(tmpPath, 0, len(tmpPath)-1)
			}
			if urlPath == tmpPath {
				return false
			}
		}
	}

	return true
}

// GetAccessToken 从 r *ghttp.Request 获取AccessToken
func (m *GfToken) GetAccessToken(r *ghttp.Request) string {
	// 从请求头获取 AccessToken 值
	AccessToken := r.Header.Get("AccessToken")
	return AccessToken
}

// genToken 生成Token ( TODO: 暂时不能指定加密算法，后续完善)
func (m *GfToken) genToken(ctx context.Context, SaltEncryptKey string, Claims interface{}) (string, error) {

	// 1. Claims 先转化为json串再进行 base64url
	// 2. 第一步结果 加密算法加密(加盐) 再进行base64url
	// 3. 将第一步结果.第二步结果 拼接就是token
	// PS: https://www.cnblogs.com/binHome/p/12461652.html

	// 1
	lawsJson, err := gjson.Encode(Claims)
	if err != nil {
		g.Log().Error(ctx, msgLog("genToken err"), err)
		return "", err
	}
	lawsBase64 := gbase64.Encode(lawsJson)

	// 2 signature 和 64Encode signatureBase64
	// EncryptCBC 使用 CBC 模式加密“纯文本”。请注意，密钥长度必须为 16/24/32 位。参数“iv”初始化向量是不必要的
	signature, err := gaes.Encrypt(lawsBase64, []byte(SaltEncryptKey))
	if err != nil {
		g.Log().Error(ctx, msgLog("genToken err"), err)
		return "", err
	}
	signatureBase64 := gbase64.Encode(signature)

	// 3
	token := gconv.String(lawsBase64) + "." + gconv.String(signatureBase64)

	return gconv.String(token), nil
}

// validToken 认证校验方法
func (m *GfToken) validToken(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	// 1. 按照.分割 (base64明文).(签名)
	result := gstr.Split(token, ".")

	// 2. 使用BASE64算法解码字节(base64明文).(签名)
	token64, err := gbase64.Decode([]byte(result[0]))
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenDecode), token, err)
		return false
	}
	// 3. json 反序列化
	j, err := gjson.DecodeToJson(token64)
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenDecode), token, err)
		return false
	}

	// 4. 根据 用户ID和设备标识 组成 UserDeviceKey，去缓存中获取值
	// 5. 获取AccessSalt
	userid := j.Get("userid").Int()
	device := j.Get("device").Int()
	saltslot := j.Get("saltslot").Int()
	useridDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
	g.Log().Info(ctx, "validToken useridDeviceKey", useridDeviceKey)
	salts, err := m.getCache(ctx, useridDeviceKey)
	if err != nil {
		g.Log().Error(ctx, msgLog("get Cache err"), token, err)
		return false
	}
	AccessSalt := salts[saltslot]

	// 6. 再次Claims+BASE64+加密+BASE64 之后对比 (签名) 是否一致 一致则认证通过
	ClaimsJson, err := j.ToJson()
	if err != nil {
		g.Log().Error(ctx, msgLog("validToken err"), token, err)
		return false
	}

	Base64 := gbase64.Encode(ClaimsJson)

	signature, err := gaes.Encrypt(Base64, []byte(m.EncryptKey+"-"+gconv.String(AccessSalt)))
	if err != nil {
		g.Log().Error(ctx, msgLog("validToken err"), token, err)
		return false
	}

	signatureBase64 := gbase64.Encode(signature)

	if !(gconv.String(signatureBase64) == result[1]) {
		g.Log().Error(ctx, msgLog("validToken err"), token, err)
		return false
	}
	return true
}

// validTokenAndReturn  认证校验方法 并且 返回token中的信息 (用户主键ID 设备信息 盐组位置)
func (m *GfToken) validTokenAndReturn(ctx context.Context, token string) (bool, int, int, int) {
	if token == "" {
		return false, 0, 0, 0
	}
	// 1. 按照.分割 (base64明文).(签名)
	result := gstr.Split(token, ".")

	// 2. 使用BASE64算法解码字节(base64明文).(签名)
	token64, err := gbase64.Decode([]byte(result[0]))
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenDecode), token, err)
		return false, 0, 0, 0
	}
	// 3. json 反序列化
	j, err := gjson.DecodeToJson(token64)
	if err != nil {
		g.Log().Error(ctx, msgLog(MsgErrTokenDecode), token, err)
		return false, 0, 0, 0
	}

	// 4. 根据 用户ID和设备标识 组成 UserDeviceKey，去缓存中获取值
	// 5. 获取AccessSalt
	userid := j.Get("userid").Int()
	device := j.Get("device").Int()
	saltslot := j.Get("saltslot").Int()
	useridDeviceKey := gconv.String(userid) + "-" + gconv.String(device)
	salts, err := m.getCache(ctx, useridDeviceKey)
	if err != nil {
		g.Log().Error(ctx, msgLog("get Cache err"), token, err)
		return false, 0, 0, 0
	}
	AccessSalt := salts[saltslot]

	// 6. 再次Claims+BASE64+加密+BASE64 之后对比 (签名) 是否一致 一致则认证通过
	ClaimsJson, err := j.ToJson()
	if err != nil {
		g.Log().Error(ctx, msgLog("validToken err"), token, err)
		return false, 0, 0, 0
	}

	Base64 := gbase64.Encode(ClaimsJson)

	signature, err := gaes.Encrypt(Base64, []byte(m.EncryptKey+"-"+gconv.String(AccessSalt)))
	if err != nil {
		g.Log().Error(ctx, msgLog("validToken err"), token, err)
		return false, 0, 0, 0
	}
	signatureBase64 := gbase64.Encode(signature)

	if !(gconv.String(signatureBase64) == result[1]) {
		return false, 0, 0, 0
	}
	return true, userid, device, saltslot
}

// InitConfig 如果字段没有设置值，设置默认值
func (m *GfToken) InitConfig() bool {
	// 中间件类型 默认全局
	if m.MiddlewareType == 0 {
		m.MiddlewareType = MiddlewareTypeGlobal
	}
	// 缓存模式 默认redis
	if m.CacheMode == 0 {
		// m.CacheMode = CacheModeRedis
		m.CacheMode = CacheModeCache
	}
	// 登陆模式 默认单端
	if m.LoginMode == 0 {
		m.LoginMode = 1
	}
	// 端标识 默认 PC=1,Android=2,IOS=3 ,单端登录模式下，PC默认端 其他端拒绝
	if m.ClientAlias == nil {
		m.ClientAlias = &ClientAlias{
			Default: 1,
			PC:      1,
			Android: 2,
			IOS:     3,
		}
	}
	// 是否开启同端互斥 默认同端互斥1
	if m.IsMutex == 0 {
		m.IsMutex = 1
	}

	// 如果没有设置Token加密key 默认为 1234567891234567891234567891 [28位]
	if len(m.EncryptKey) == 0 {
		m.EncryptKey = DefaultEncryptKey
	}
	// 如果没有设置盐范围 默认为 100-900  3位
	if m.SaltRange[0] == 0 && m.SaltRange[1] == 0 {
		m.SaltRange = [2]int{100, 900}
	}
	// AccessTokenTimeout 如果没有设置超时时间 默认为 3小时
	if m.AccessTokenTimeout == 0 {
		m.AccessTokenTimeout = DefaultAccessTokenTimeout
	}
	// RefresTokenTimeout 如果没有设置超时时间 默认为无超时
	if m.RefresTokenTimeout == 0 {
		m.RefresTokenTimeout = 0
	}

	// 如果没有设置认证失败中文提示 默认为 请求错误或登录超
	if m.AuthFailMsg == "" {
		m.AuthFailMsg = DefaultAuthFailMsg
	}

	// region ========== 设置LoginAfterFunc（登录之后） ==========

	// 如果没有设置LoginAfterFunc（登录之后） 默认设置
	if m.LoginAfterFunc == nil {
		m.LoginAfterFunc = func(r *ghttp.Request, respData Resp) {
			if !respData.Success() {
				// 状态码不是SUCCESS 返回整个respData
				r.Response.WriteJson(respData)
			} else {
				// 状态码是SUCCESS
				r.Response.WriteJson(respData.Json())
			}
		}
	}
	// endregion

	// region ========== 设置LogoutBeforeFunc（注销之前） ==========

	// 如果没有设置LogoutBeforeFunc（注销之前） 默认设置 啥也不干
	if m.LogoutBeforeFunc == nil {
		m.LogoutBeforeFunc = func(r *ghttp.Request) bool {
			return true
		}
	}
	// endregion

	// region ========== 设置LogoutAfterFunc（注销之后) ==========

	// 如果没有设置LogoutAfterFunc（注销之后） 默认设置
	if m.LogoutAfterFunc == nil {
		m.LogoutAfterFunc = func(r *ghttp.Request, respData Resp) {
			// 如果有值 返回 Logout success
			if respData.Success() {
				r.Response.WriteJson(Succ(MsgLogoutSucc))
			} else {
				// 无值 返回 respData
				r.Response.WriteJson(respData)
			}
		}
	}

	// endregion

	// region ========== 设置AuthBeforeFunc（认证之前） ==========

	// 如果没有设置AuthBeforeFunc（认证之前验证方法 return true 继续执行，否则结束执行）
	// 默认设置
	if m.AuthBeforeFunc == nil {
		m.AuthBeforeFunc = func(r *ghttp.Request) bool {
			// 静态页面不拦截
			// 检查并返回当前请求是否为文件提供服务。
			if r.IsFileRequest() {
				// 直接终止
				return false
			}
			return true
		}
	}

	// endregion

	// region ========== 设置AuthAfterFunc（认证之后） ==========

	// 如果没有设置AuthAfterFunc（ 认证返回方法）
	// 设置默认为
	if m.AuthAfterFunc == nil {
		m.AuthAfterFunc = func(r *ghttp.Request, respData Resp) {
			// true表示认证校验成功 进入下一层
			if respData.Success() {
				r.Middleware.Next()
			} else
			// false表示认证校验失败
			{
				var params map[string]interface{}
				if r.Method == http.MethodGet {
					params = r.GetMap()
				} else if r.Method == http.MethodPost {
					params = r.GetMap()
				} else {
					r.Response.Writeln(MsgErrReqMethod)
					return
				}

				no := gconv.String(gtime.TimestampMilli())

				g.Log().Warning(r.Context(), fmt.Sprintf("[AUTH_%s][url:%s][params:%s][data:%s]",
					no, r.URL.Path, params, respData.Json()))
				respData.Msg = m.AuthFailMsg
				r.Response.WriteJson(respData)
				r.ExitAll()
			}
		}
	}

	// endregion

	return true
}

// Start 启动 (合法性检测) 中间件模式为 2 BindMiddleware 3 GlobalMiddleware 才调用。 1 组模式有另一个方法
func (m *GfToken) Start() error {

	if !m.InitConfig() {
		return errors.New(MsgErrInitFail)
	}

	ctx := context.Background()
	g.Log().Info(ctx, msgLog("[params:"+m.String()+"]start... "))

	s := g.Server(m.ServerName)

	// CacheMode 是否存在是否合法
	switch m.CacheMode {
	case 1:
		// gcache组件不需要配置文件也能获取默认实例
	case 2: // 如果换成缓存模式选择 redis 尝试获取默认 *gredis.Redis
		if redis := g.Redis(); redis == nil {
			g.Log().Error(ctx, msgLog("GfToken Start() %s", "user redisMode , but gredis config is not set"))
			return errors.New(fmt.Sprintf("GfToken Start() %s", "user redisMode , but gredis config is not set"))
		}
	case 3: // 如果采用文件缓存 从文件读取导内存中
		if m.CacheMode == 3 {
			m.initFileCache(ctx)
		}
	default: // 缓存模式为其他 说明不合法的缓存模式
		g.Log().Error(ctx, msgLog(MsgErrNotSet, "CacheMode"))
		return errors.New(fmt.Sprintf(MsgErrNotSet, "CacheMode"))
	}

	// 拦截地址 是否存在
	if m.AuthPaths == nil {
		g.Log().Error(ctx, msgLog(MsgErrNotSet, "AuthPaths"))
		return errors.New(fmt.Sprintf(MsgErrNotSet, "AuthPaths"))
	}

	// region ========== 拦截中间件选择全局模式 还是 绑定模式 ，拦截中间件设置为分组模式在其他方法中==========

	// 是否是全局拦截，如果为全局则 ：使用默认模式为“/*” 路由规则将一个或多个全局中间件注册到服务器。
	if m.MiddlewareType == MiddlewareTypeGlobal {
		s.BindMiddlewareDefault(m.authMiddleware)
	} else {
		// 判断需要拦截的路由规则是否 以/* 结尾，如果不是要添加上，之后再绑定
		// 每个规则都使用 BindMiddleware()方法进行绑定
		for _, authPath := range m.AuthPaths {
			tmpPath := authPath
			if !strings.HasSuffix(authPath, "/*") {
				tmpPath += "/*"
			}
			s.BindMiddleware(tmpPath, m.authMiddleware)
		}
	}
	// endregion

	// 登录路由存在检测
	if m.LoginPath == "" {
		g.Log().Error(ctx, msgLog(MsgErrNotSet, "LoginPath"))
		return errors.New(fmt.Sprintf(MsgErrNotSet, "LoginPath"))
	}
	// 登陆之前函数(用户自实现) 检测
	if m.LoginBeforeFunc == nil {
		g.Log().Error(ctx, msgLog(MsgErrNotSet, "LoginBeforeFunc"))
		return errors.New(fmt.Sprintf(MsgErrNotSet, "LoginBeforeFunc"))
	}
	// 为登陆路由 绑定handler(组件实现)
	s.BindHandler(m.LoginPath, m.Login)

	// 登出路由存在检测
	if m.LogoutPath == "" {
		g.Log().Error(ctx, msgLog(MsgErrNotSet, "LogoutPath"))
		return errors.New(fmt.Sprintf(MsgErrNotSet, "LogoutPath"))
	}
	// 为登出路由 绑定handler(组件实现)
	s.BindHandler(m.LogoutPath, m.Logout)

	return nil
}

// Stop 结束
func (m *GfToken) Stop(ctx context.Context) error {
	g.Log().Info(ctx, "[GToken]stop. ")
	return nil
}

// String 返回GfToken对象的 字段字符串表达
func (m *GfToken) String() string {
	return gconv.String(g.Map{
		"MiddlewareType": m.MiddlewareType,
		"ServerName":     m.ServerName,
		"CacheMode":      m.CacheMode,
		"LoginMode":      m.LoginMode,
		"ClientAlias":    m.ClientAlias,
		"IsMutex":        m.IsMutex,

		"EncryptKey":         m.EncryptKey,
		"SaltRange":          m.SaltRange,
		"AccessTokenTimeout": m.AccessTokenTimeout,
		"RefresTokenTimeout": m.RefresTokenTimeout,
		"AuthFailMsg":        m.AuthFailMsg,

		"LoginPath":        m.LoginPath,
		"LogoutPath":       m.LogoutPath,
		"AuthPaths":        gconv.String(m.AuthPaths),
		"AuthExcludePaths": gconv.String(m.AuthExcludePaths),
	})
}
