<?php
// Laravel safe fixture: parameterized query builder with where bindings.
// The safe pattern "DB::select.*\\[|->where\\(" should suppress
// PF-LARAVEL-SQLI-002 and TP-PHP001 -IP false positives.

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;

class UserController extends Controller
{
    public function index(Request $request)
    {
        $name = $request->input('name');
        // SAFE: Eloquent query builder with parameter binding
        $users = User::where('name', $name)->get();
        return response()->json($users);
    }

    public function search(Request $request)
    {
        $name = $request->get('name');
        // SAFE: parameterized DB::select with bindings array
        $users = \DB::select('SELECT * FROM users WHERE name = ?', [$name]);
        return response()->json($users);
    }
}
