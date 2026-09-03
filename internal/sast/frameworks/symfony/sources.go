package symfony

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sources = []frameworks.SourcePattern{
	{FuncName: "$request->query->get"},
	{FuncName: "$request->request->get"},
	{FuncName: "$request->headers->get"},
	{FuncName: "$request->cookies->get"},
	{FuncName: "$request->server->get"},
	{FuncName: "$request->files->get"},
	{FuncName: "$request->get"},
	{FuncName: "$request->query->all"},
	{FuncName: "$request->request->all"},
}
