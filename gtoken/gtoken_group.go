package gtoken

import (
	"context"
	"errors"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/text/gstr"
	"github.com/gogf/gf/v2/util/gconv"
)

// Middleware 为group绑定中间件
func (m *GfToken) Middleware(ctx context.Context, group *ghttp.RouterGroup) error {
	// 如果初始化失败，直接返回
	if !m.InitConfig() {
		return errors.New("InitConfig fail")
	}

	// 拦截模式设置为 组模式
	m.MiddlewareType = MiddlewareTypeGroup
	g.Log().Info(ctx, "[GToken][params:"+m.String()+"]start... ")

	// 缓存模式不能大于CacheModeFile
	if m.CacheMode > CacheModeFile {
		g.Log().Error(ctx, "[GToken]CacheMode set error")
		return errors.New("CacheMode set error")
	}

	//`len(Key)+1+len(SaltRange)==32`
	if len(m.EncryptKey)+1+len(gconv.SliceInt(m.SaltRange[0])) == 32 {
		g.Log().Error(ctx, "[GToken] The lengths of encryptkey and saltrange are not 31 in total ")
		return errors.New("The lengths of encryptkey and saltrange are not 31 in total")
	}

	// 登录路由规则为空 或者 登录之前 handler 未设置，直接返回错误
	if m.LoginPath == "" || /* 或者 */ m.LoginBeforeFunc == nil {
		g.Log().Error(ctx, "[GToken]LoginPath or LoginBeforeFunc not set")
		return errors.New("LoginPath or LoginBeforeFunc not set")
	}

	// 登出路由规则为空 ，直接返回错误
	if m.LogoutPath == "" {
		g.Log().Error(ctx, "[GToken]LogoutPath not set")
		return errors.New("LogoutPath not set")
	}

	// 为组路由规则 绑定认证拦截中间件
	// 当请求path 通过匹配发现 符合组路由规则，调用链包含 m.authMiddleware
	group.Middleware(m.authMiddleware)

	// 为group中添加 登录路由 登出路由绑定handler m.Login m.Logout
	registerFunc(ctx, group, m.LoginPath, m.Login)
	registerFunc(ctx, group, m.LogoutPath, m.Logout)

	return nil
}

// 如果包含请求方式，按照请求方式注册；默认注册所有
func registerFunc(ctx context.Context, group *ghttp.RouterGroup, pattern string, object interface{}) {
	// 判断pattern是否包含请求方式，有则使用*ghttp.RouterGroup.Map()方法注册；
	if gstr.Contains(pattern, ":") || /* 或者 */ gstr.Contains(pattern, "@") {
		group.Map(map[string]interface{}{
			pattern: object,
		})
	} else
	// 默认注册所有
	{
		group.ALL(pattern, object)
	}
}
