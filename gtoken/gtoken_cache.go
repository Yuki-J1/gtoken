package gtoken

import (
	"context"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/util/gconv"
)

// setCache 设置缓存 默认有效期无到期
// userIDDeviceKey string : 用户ID+设备ID
// value []int : RefresSalt.AccessSalt
func (m *GfToken) setCache(ctx context.Context, userIDDeviceKey string, value []int) error {
	switch m.CacheMode {
	// region ========== 缓存模式 1 3 ==========
	case CacheModeCache, CacheModeFile:
		err := gcache.Set(ctx, userIDDeviceKey, value, 0)
		g.Log().Info(ctx, "setCache", userIDDeviceKey, gconv.Ints(value))
		if err != nil {
			g.Log().Error(ctx, "[GToken] gcache.Set SETEX ", err)
			return gerror.New("gcache.Set")
		}

		if m.CacheMode == CacheModeFile {
			// 刷新 将内存缓存中的数据写入到文件中
			m.writeFileCache(ctx)
		}
	// endregion
	// region ========== 缓存模式 2 reids ==========
	case CacheModeRedis:
		_, err := g.Redis().Do(ctx, "SETEX", userIDDeviceKey, value)
		if err != nil {
			g.Log().Error(ctx, "[GToken] gredis SETEX ", err)
			return gerror.New("gredis SETEX")
		}
	// endregion
	default:
		return gerror.New("cache model error")
	}
	return nil
}

// getCache 获取缓存
// userIDDeviceKey string : 用户ID+设备ID
// []int : RefresSalt.AccessSalt
func (m *GfToken) getCache(ctx context.Context, userIDDeviceKey string) ([]int, error) {
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		// region ========== 缓存模式为本地 或者 文件 ==========
		value, err := gcache.Get(ctx, userIDDeviceKey)
		g.Log().Info(ctx, "getCache value", userIDDeviceKey, value.Ints())
		if err != nil {
			g.Log().Error(ctx, "[GToken]cache get error", err)
			return make([]int, 10), gerror.New("cache get error")
		}
		if value.IsNil() {
			return make([]int, 10), gerror.New(MsgErrCacheNoFound)
		}
		return value.Ints(), nil
		// endregion
	case CacheModeRedis:
		// region ========== 缓存模式为redis ==========
		value, err := g.Redis().Do(ctx, "GET", userIDDeviceKey)
		if err != nil {
			g.Log().Error(ctx, "[GToken]cache get error", err)
			return make([]int, 10), gerror.New("cache get error")
		}
		if value.IsNil() {
			return make([]int, 10), gerror.New(MsgErrCacheNoFound)
		}
		return value.Ints(), nil
		// endregion
	default:
		return make([]int, 10), gerror.New("cache model error")
	}
	return make([]int, 10), gerror.New("other err")

}

// removeCache 删除缓存
// userIDDeviceKey string : 用户ID+设备ID
func (m *GfToken) removeCache(ctx context.Context, userIDDeviceKey string) error {
	switch m.CacheMode {
	case CacheModeCache, CacheModeFile:
		_, err := gcache.Remove(ctx, userIDDeviceKey)
		if err != nil {
			g.Log().Error(ctx, err)
		}
		if m.CacheMode == CacheModeFile {
			// 刷新 将内存缓存中的数据写入到文件中
			m.writeFileCache(ctx)
		}
	case CacheModeRedis:
		var err error
		_, err = g.Redis().Do(ctx, "DEL", userIDDeviceKey)
		if err != nil {
			g.Log().Error(ctx, "[GToken]cache remove error", err)
			return gerror.New("cache remove error")
		}
	default:
		return gerror.New("cache model error")
	}
	return gerror.New("other error")
}

// region ========== 文件缓存模式下 加载到内存 保存到文件==========

// 将内存缓存中的数据写入到文件中
func (m *GfToken) writeFileCache(ctx context.Context) {
	// 获取系统临时文件 和 gtoken.dat 拼凑为文件路径
	// /tmp/gtoken.dat
	file := gfile.Temp(CacheModeFileDat)
	data, e := gcache.Data(ctx)
	if e != nil {
		g.Log().Error(ctx, "[GToken]cache writeFileCache error", e)
	}
	// 以json格式写入文件
	gfile.PutContents(file, gjson.New(data).MustToJsonString())
}

// 从文件中读取到内存缓存中
func (m *GfToken) initFileCache(ctx context.Context) {
	// 获取系统临时文件 和 gtoken.dat 拼凑为文件路径
	// /tmp/gtoken.dat
	file := gfile.Temp(CacheModeFileDat)
	// 检查文件是否存在，不存在直接返回
	if !gfile.Exists(file) {
		return
	}
	// 读取文件内容 (json)
	data := gfile.GetContents(file)
	// 将文件内容转换为 map[string]interface{}
	maps := gconv.Map(data)
	if maps == nil || /* 或 */ len(maps) <= 0 {
		return
	}
	// 将内容保持在内存缓存中 有效期not expire
	for k, v := range maps {
		gcache.Set(ctx, k, v, 0)
	}
}

// endregion
