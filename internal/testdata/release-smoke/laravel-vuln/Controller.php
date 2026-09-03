<?php
// Laravel vulnerable fixture: raw SQL with string concatenation.
// PF-LARAVEL-SQLI-002 should fire on the DB::raw with concatenation.

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserController extends Controller
{
    public function search(Request $request)
    {
        $name = $request->get('name');
        // VULNERABLE: raw SQL with string concatenation
        $users = \DB::select('SELECT * FROM users WHERE name = \'' . $name . '\'');
        return response()->json($users);
    }

    public function redirect(Request $request)
    {
        $url = $request->input('url');
        // VULNERABLE: open redirect
        return redirect()->away($url);
    }
}
