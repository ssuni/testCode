<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenInvalidException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;


class Authenticate extends Middleware
{
    public function handle($request, Closure $next, ...$guards)
    {
        try {
            if($guards[0] == 'every') return $next($request);
            JWTAuth::parseToken()->authenticate();
        } catch (Exception $e) {
            if ($e instanceof TokenInvalidException) {
                return response()->json(['status' => 'Token is Invalid'], 403);
            } else if ($e instanceof TokenExpiredException) {
                return response()->json(['status' => 'Token is Expired'], 401);
            } else if ($e instanceof TokenBlacklistedException) {
                return response()->json(['status' => 'Token is Blacklisted'], 400);
            } else {
                return response()->json(['status' => 'Authorization Token not found'], 404);
            }
        }
        return $next($request);
    }

    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @param \Illuminate\Http\Request $request
     * @return string|null
     */
    protected function redirectTo($request)
    {
        if (!$request->expectsJson()) {
            return route('login');
        }
    }
}
