package audit

import (
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/lua"
)

func RecoverByCodeVM(L *lua.LState, ev *Event) {
	r := recover()
	if r == nil {
		return
	}
	ev.Subject("进程服务异常").From(L.CodeVM()).Msg(catch.StackTrace(0)).Log().Put()
}

func Recover(ev *Event) {
	r := recover()
	if r == nil {
		return
	}
	ev.Subject("进程异常").Msg(catch.StackTrace(0)).Log().Put()
}
