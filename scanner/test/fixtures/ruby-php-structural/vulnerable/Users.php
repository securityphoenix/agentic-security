<?php
use Illuminate\Support\Facades\DB;
class UsersController {
  public function find($request) {
    $name = $request->input('name');
    return DB::select(DB::raw("SELECT * FROM users WHERE name='" . $name . "'"));
  }
}
