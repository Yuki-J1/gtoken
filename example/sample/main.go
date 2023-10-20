package main

import (
	"context"
	"github.com/goflyfox/gtoken/gtoken"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcfg"
)

var TestServerName string

// var TestServerName string = "gtoken"

func main() {
	ctx := context.TODO()

	g.Log().Info(ctx, "########service start...")

	if fileConfig, ok := g.Cfg().GetAdapter().(*gcfg.AdapterFile); ok {
		fileConfig.SetPath("example/sample")
	}

	s := g.Server(TestServerName)
	initRouter(s)

	g.Log().Info(ctx, "########service finish.")
	s.SetPort(8999)
	s.Run()
}

var gfToken *gtoken.GfToken
var gfAdminToken *gtoken.GfToken

/*
统一路由注册
*/
func initRouter(s *ghttp.Server) {
	ctx := context.TODO()

	// 不认证接口
	s.Group("/", func(group *ghttp.RouterGroup) {
		// 添加跨域中间件
		group.Middleware(CORS)
		// 调试路由
		group.ALL("/hello", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("hello"))
		})
	})
	// region ========== 准备GfToken对象用于用户接口 ==========

	// 登陆前置函数 返回设备ID 和 用户ID
	loginFunc := LoginBeforeFunc
	// 启动gtoken
	gfToken = &gtoken.GfToken{
		ServerName:       TestServerName,
		LoginPath:        "/login", // 登陆路由规则，默认注册全部http方法
		LoginBeforeFunc:  loginFunc,
		LogoutPath:       "/user/logout",
		AuthExcludePaths: g.SliceStr{"/user/info", "/system/user/info"}, // 不拦截路径 /user/info,/system/user/info,/system/user,
	}
	// endregion
	s.Group("/", func(group *ghttp.RouterGroup) {
		// 添加跨域中间件
		group.Middleware(CORS)
		// 添加gtoken认证中间件
		err := gfToken.Middleware(ctx, group)
		if err != nil {
			panic(err)
		}
		// 为路由规则绑定handler (默认支持全部HTTP方法)
		group.ALL("/system/user", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("system user"))
		})
		group.ALL("/user/data", func(r *ghttp.Request) {
			r.Response.WriteJson(gfToken.GetAccessToken(r))
		})
		group.ALL("/user/info", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("user info"))
		})
		group.ALL("/system/user/info", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("system user info"))
		})
	})

	// region ========== 准备GfToken对象用于admin接口 ==========

	// 启动gtoken
	gfAdminToken = &gtoken.GfToken{
		ServerName: TestServerName,
		// Timeout:         10 * 1000,
		LoginPath:        "/login",
		LoginBeforeFunc:  loginFunc,
		LogoutPath:       "/user/logout",
		AuthExcludePaths: g.SliceStr{"/admin/user/info", "/admin/system/user/info"}, // 不拦截路径 /user/info,/system/user/info,/system/user,
	}

	// endregion
	s.Group("/admin", func(group *ghttp.RouterGroup) {
		// 添加跨域中间件
		group.Middleware(CORS)
		// 添加gtoken认证中间件
		err := gfAdminToken.Middleware(ctx, group)
		if err != nil {
			panic(err)
		}
		// 为路由规则绑定handler (默认支持全部HTTP方法)
		group.ALL("/system/user", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("system user"))
		})
		group.ALL("/user/info", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("user info"))
		})
		group.ALL("/system/user/info", func(r *ghttp.Request) {
			r.Response.WriteJson(gtoken.Succ("system user info"))
		})
	})
}

// LoginBeforeFunc 返回设备ID 和 用户ID
func LoginBeforeFunc(r *ghttp.Request) (int8, int8) {
	username := r.Get("username").String()
	passwd := r.Get("passwd").String()

	if username == "" || passwd == "" {
		r.Response.WriteJson(gtoken.Fail("账号或密码错误."))
		r.ExitAll()
	}
	return 1, 6
}

// CORS 跨域
func CORS(r *ghttp.Request) {
	r.Response.CORSDefault()
	r.Middleware.Next()
}
