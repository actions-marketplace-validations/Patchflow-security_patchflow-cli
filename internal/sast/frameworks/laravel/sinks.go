package laravel

import "github.com/Patchflow-security/patchflow-cli/internal/sast/frameworks"

var Sinks = []frameworks.SinkPattern{
	{FuncName: "DB::raw", ArgIndex: 0},
	{FuncName: "DB::select", ArgIndex: 0},
	{FuncName: "DB::statement", ArgIndex: 0},
	{FuncName: "DB::insert", ArgIndex: 0},
	{FuncName: "DB::update", ArgIndex: 0},
	{FuncName: "DB::delete", ArgIndex: 0},
	{FuncName: "DB::unprepared", ArgIndex: 0},
	{FuncName: "whereRaw", ArgIndex: 0},
	{FuncName: "selectRaw", ArgIndex: 0},
	{FuncName: "havingRaw", ArgIndex: 0},
	{FuncName: "orderByRaw", ArgIndex: 0},
	{FuncName: "groupByRaw", ArgIndex: 0},
	{FuncName: "away", ArgIndex: 0},
	{FuncName: "redirect", ArgIndex: 0},
	{FuncName: "unserialize", ArgIndex: 0},
	{FuncName: "Storage::put", ArgIndex: 1},
	{FuncName: "View::make", ArgIndex: -1},
	{FuncName: "create", ArgIndex: 0},
	{FuncName: "file_get_contents", ArgIndex: 0},
	{FuncName: "curl_exec", ArgIndex: 0},
}
