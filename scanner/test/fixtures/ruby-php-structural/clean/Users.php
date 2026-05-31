<?php
use Illuminate\Support\Facades\DB;
class UsersController {
  public function find($request) {
    return DB::select('SELECT * FROM users WHERE name=?', [$request->input('name')]);
  }
}
