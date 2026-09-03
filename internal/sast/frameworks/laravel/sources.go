package laravel

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "request"},
	{FuncName: "request()"},
	{FuncName: "$request->input"},
	{FuncName: "$request->query"},
	{FuncName: "$request->get"},
	{FuncName: "$request->all"},
	{FuncName: "$request->only"},
	{FuncName: "$request->except"},
	{FuncName: "$request->json"},
	{FuncName: "$request->cookie"},
	{FuncName: "$request->header"},
	{FuncName: "$request->file"},
	{FuncName: "Input::get"},
	{FuncName: "Input::all"},
	{FuncName: "$_GET", IsSubscript: true},
	{FuncName: "$_POST", IsSubscript: true},
	{FuncName: "$_REQUEST", IsSubscript: true},
	{FuncName: "$_COOKIE", IsSubscript: true},
}
